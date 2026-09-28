package beacon

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func backupRecords(t *testing.T, archive []byte) ([]byte, [][]byte) {
	t.Helper()
	prefixLen := len(backupMagic) + backupArchiveID
	if len(archive) < prefixLen {
		t.Fatal("backup header too short")
	}
	prefix := append([]byte(nil), archive[:prefixLen]...)
	var records [][]byte
	for pos := prefixLen; pos < len(archive); {
		if len(archive)-pos < 4 {
			t.Fatal("backup frame length truncated")
		}
		n := int(binary.BigEndian.Uint32(archive[pos : pos+4]))
		end := pos + 4 + n
		if n <= 0 || end > len(archive) {
			t.Fatal("backup frame truncated")
		}
		records = append(records, append([]byte(nil), archive[pos:end]...))
		pos = end
	}
	return prefix, records
}

func backupRejects(t *testing.T, archive []byte, key []byte) {
	t.Helper()
	if err := DecryptBackup(bytes.NewReader(archive), &bytes.Buffer{}, key); err == nil {
		t.Fatal("malformed backup accepted")
	}
}

func TestBackupRoundTripAndAuthentication(t *testing.T) {
	plain := []byte(strings.Repeat("synthetic dump data\x00", backupChunk*2/7))
	key := bytes.Repeat([]byte{7}, 32)
	var encrypted bytes.Buffer
	if err := EncryptBackup(bytes.NewReader(plain), &encrypted, key); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("synthetic dump data")) {
		t.Fatal("backup contains plaintext")
	}
	var restored bytes.Buffer
	if err := DecryptBackup(bytes.NewReader(encrypted.Bytes()), &restored, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), plain) {
		t.Fatal("backup round trip changed the dump")
	}
	wrong := bytes.Repeat([]byte{8}, 32)
	if err := DecryptBackup(bytes.NewReader(encrypted.Bytes()), &bytes.Buffer{}, wrong); err == nil {
		t.Fatal("wrong backup key accepted")
	}
	prefix, records := backupRecords(t, encrypted.Bytes())
	for i := 0; i < len(records); i++ {
		cut := append([]byte(nil), prefix...)
		for _, record := range records[:i] {
			cut = append(cut, record...)
		}
		backupRejects(t, cut, key)
		if i < len(records) {
			partial := append([]byte(nil), cut...)
			if len(partial) > len(prefix) {
				partial = partial[:len(partial)-1]
			}
			backupRejects(t, partial, key)
		}
	}
	tampered := append([]byte(nil), encrypted.Bytes()...)
	tampered[len(tampered)-5] ^= 1
	if err := DecryptBackup(bytes.NewReader(tampered), &bytes.Buffer{}, key); err == nil {
		t.Fatal("tampered backup accepted")
	}
	trailing := append(append([]byte(nil), encrypted.Bytes()...), 0x99)
	backupRejects(t, trailing, key)
}

func TestBackupRejectsInvalidFrameSequencesAndCrossArchiveSplice(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var a, b bytes.Buffer
	if err := EncryptBackup(bytes.NewReader(bytes.Repeat([]byte("A"), backupChunk*2)), &a, key); err != nil {
		t.Fatal(err)
	}
	if err := EncryptBackup(bytes.NewReader(bytes.Repeat([]byte("B"), backupChunk*2)), &b, key); err != nil {
		t.Fatal(err)
	}
	ap, ar := backupRecords(t, a.Bytes())
	bp, br := backupRecords(t, b.Bytes())
	if len(ar) < 3 || len(br) < 3 {
		t.Fatal("test archive did not contain two data frames and a footer")
	}
	missing := append(append([]byte(nil), ap...), ar[0]...)
	missing = append(missing, ar[2]...)
	backupRejects(t, missing, key)
	reordered := append(append([]byte(nil), ap...), ar[1]...)
	reordered = append(reordered, ar[0]...)
	reordered = append(reordered, ar[2]...)
	backupRejects(t, reordered, key)
	duplicated := append(append([]byte(nil), ap...), ar[0]...)
	duplicated = append(duplicated, ar[0]...)
	for _, record := range ar[1:] {
		duplicated = append(duplicated, record...)
	}
	backupRejects(t, duplicated, key)
	spliced := append(append([]byte(nil), ap...), ar[0]...)
	for _, record := range br[1:] {
		spliced = append(spliced, record...)
	}
	backupRejects(t, spliced, key)
	_ = bp
}

func TestBackupRejectsForgedEmptyCompletion(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	aead, err := backupAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	archiveID := bytes.Repeat([]byte{3}, backupArchiveID)
	var forged bytes.Buffer
	forged.WriteString(backupMagic)
	forged.Write(archiveID)
	if err := writeBackupFrame(&forged, aead, archiveID, 0, []byte{backupDataMarker}); err != nil {
		t.Fatal(err)
	}
	backupRejects(t, forged.Bytes(), key)
}

func TestTrustedProxyForwardingIsExplicit(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	app := &App{}
	if got := app.clientHost(request); got != "192.0.2.10" {
		t.Fatalf("untrusted forwarded address was used: %s", got)
	}
	_, network, _ := net.ParseCIDR("192.0.2.0/24")
	app.trustedProxies = []*net.IPNet{network}
	if got := app.clientHost(request); got != "198.51.100.7" {
		t.Fatalf("trusted forwarded address was not used: %s", got)
	}
}
