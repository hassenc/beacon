package beacon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	backupMagic       = "BEACON-BACKUP-V2\n"
	backupChunk       = 1 << 20
	backupArchiveID   = 16
	backupDataMarker  = byte(1)
	backupFinalMarker = byte(0xff)
)

func backupAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("backup key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func backupAAD(archiveID []byte, sequence uint64) []byte {
	aad := make([]byte, 0, len("beacon backup v2")+len(archiveID)+8)
	aad = append(aad, "beacon backup v2"...)
	aad = append(aad, archiveID...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	return append(aad, seq[:]...)
}

func backupWriteAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeBackupFrame(w io.Writer, aead cipher.AEAD, archiveID []byte, sequence uint64, plain []byte) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, backupAAD(archiveID, sequence))
	frameLen := len(nonce) + len(sealed)
	if frameLen > int(^uint32(0)) {
		return errors.New("backup frame is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(frameLen))
	if err := backupWriteAll(w, size[:]); err != nil {
		return err
	}
	if err := backupWriteAll(w, nonce); err != nil {
		return err
	}
	return backupWriteAll(w, sealed)
}

// EncryptBackup writes an authenticated, bounded-memory backup. Each frame is
// bound to a random archive ID and sequence number, and an authenticated final
// frame records the complete plaintext length. There is no unauthenticated EOF
// or zero-length completion marker.
func EncryptBackup(r io.Reader, w io.Writer, key []byte) error {
	aead, err := backupAEAD(key)
	if err != nil {
		return err
	}
	if err = backupWriteAll(w, []byte(backupMagic)); err != nil {
		return err
	}
	archiveID := make([]byte, backupArchiveID)
	if _, err = io.ReadFull(rand.Reader, archiveID); err != nil {
		return err
	}
	if err = backupWriteAll(w, archiveID); err != nil {
		return err
	}
	buf := make([]byte, backupChunk)
	var sequence, total uint64
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			if total > ^uint64(0)-uint64(n) {
				return errors.New("backup is too large")
			}
			plain := make([]byte, n+1)
			plain[0] = backupDataMarker
			copy(plain[1:], buf[:n])
			if err = writeBackupFrame(w, aead, archiveID, sequence, plain); err != nil {
				return err
			}
			sequence++
			total += uint64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	footer := make([]byte, 9)
	footer[0] = backupFinalMarker
	binary.BigEndian.PutUint64(footer[1:], total)
	return writeBackupFrame(w, aead, archiveID, sequence, footer)
}

func DecryptBackup(r io.Reader, w io.Writer, key []byte) error {
	aead, err := backupAEAD(key)
	if err != nil {
		return err
	}
	header := make([]byte, len(backupMagic))
	if _, err = io.ReadFull(r, header); err != nil || string(header) != backupMagic {
		return errors.New("invalid Beacon backup header")
	}
	archiveID := make([]byte, backupArchiveID)
	if _, err = io.ReadFull(r, archiveID); err != nil {
		return errors.New("truncated Beacon backup header")
	}
	maxFrame := uint32(backupChunk + 1 + aead.NonceSize() + aead.Overhead())
	var sequence, total uint64
	for {
		var size [4]byte
		if _, err = io.ReadFull(r, size[:]); err != nil {
			return errors.New("truncated Beacon backup: authenticated completion frame missing")
		}
		frameLen := binary.BigEndian.Uint32(size[:])
		if frameLen == 0 || frameLen > maxFrame {
			return errors.New("invalid Beacon backup frame length")
		}
		frame := make([]byte, frameLen)
		if _, err = io.ReadFull(r, frame); err != nil {
			return errors.New("truncated Beacon backup frame")
		}
		if len(frame) < aead.NonceSize()+aead.Overhead() {
			return errors.New("invalid Beacon backup frame")
		}
		plain, err := aead.Open(nil, frame[:aead.NonceSize()], frame[aead.NonceSize():], backupAAD(archiveID, sequence))
		if err != nil {
			return errors.New("Beacon backup authentication failed")
		}
		sequence++
		switch {
		case len(plain) >= 1 && plain[0] == backupDataMarker:
			if len(plain) == 1 {
				return errors.New("empty Beacon backup data frame")
			}
			if total > ^uint64(0)-uint64(len(plain)-1) {
				return errors.New("Beacon backup length overflow")
			}
			if err = backupWriteAll(w, plain[1:]); err != nil {
				return err
			}
			total += uint64(len(plain) - 1)
		case len(plain) == 9 && plain[0] == backupFinalMarker:
			if binary.BigEndian.Uint64(plain[1:]) != total {
				return errors.New("Beacon backup length check failed")
			}
			var extra [1]byte
			if n, readErr := io.ReadFull(r, extra[:]); n != 0 || readErr != io.EOF {
				return errors.New("trailing data after Beacon backup")
			}
			return nil
		default:
			return errors.New("invalid Beacon backup completion frame")
		}
	}
}
