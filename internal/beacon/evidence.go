package beacon

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type envelope struct{ Key, Data []byte }

func (c *Crypto) SealEnvelope(data []byte, id string) []byte {
	key := make([]byte, 32)
	rand.Read(key)
	local, _ := NewCrypto(key)
	b, _ := json.Marshal(envelope{c.Seal(key, "key:"+id), local.Seal(data, id)})
	return b
}
func (c *Crypto) OpenEnvelope(b []byte, id string) ([]byte, error) {
	var env envelope
	if e := json.Unmarshal(b, &env); e != nil {
		return nil, e
	}
	key, e := c.Open(env.Key, "key:"+id)
	if e != nil {
		return nil, e
	}
	local, e := NewCrypto(key)
	if e != nil {
		return nil, e
	}
	return local.Open(env.Data, id)
}
func (s *Store) saveEvidence(ctx context.Context, tx *sql.Tx, ref string, files []Attachment) error {
	for _, f := range files {
		if f.Data == nil {
			continue
		}
		if Hash(string(f.Data)) != f.SHA256 {
			return errors.New("evidence checksum mismatch")
		}
		b := s.Crypto.SealEnvelope(f.Data, "evidence:"+ref+":"+f.ID)
		if _, e := tx.ExecContext(ctx, "INSERT INTO evidence(id,case_ref,encrypted,size) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING", f.ID, ref, b, len(f.Data)); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) detachEvidence(ctx context.Context, tx *sql.Tx, c *Case) error {
	if e := s.saveEvidence(ctx, tx, c.Ref, c.Payload.Attachments); e != nil {
		return e
	}
	for i := range c.Payload.Attachments {
		f := &c.Payload.Attachments[i]
		if f.Data != nil {
			f.Size = len(f.Data)
			f.Data = nil
		}
	}
	return nil
}
func (s *Store) Evidence(ctx context.Context, ref, id string) ([]byte, error) {
	var b []byte
	if e := s.DB.QueryRowContext(ctx, "SELECT encrypted FROM evidence WHERE case_ref=$1 AND id=$2", ref, id).Scan(&b); e != nil {
		return nil, e
	}
	return s.Crypto.OpenEnvelope(b, "evidence:"+ref+":"+id)
}
func (s *Store) upgradePayloads(ctx context.Context, tx *sql.Tx) error {
	rows, e := tx.QueryContext(ctx, "SELECT ref FROM cases ORDER BY ref")
	if e != nil {
		return e
	}
	var refs []string
	for rows.Next() {
		var ref string
		if e = rows.Scan(&ref); e != nil {
			rows.Close()
			return e
		}
		refs = append(refs, ref)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, ref := range refs {
		var b []byte
		if e = tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1", ref).Scan(&b); e != nil {
			return e
		}
		var d diskCase
		if e = json.Unmarshal(b, &d); e != nil {
			return e
		}
		if len(d.WrappedKey) > 0 {
			continue
		}
		c, e := s.decode(b)
		if e != nil {
			return e
		}
		if e = s.detachEvidence(ctx, tx, &c); e != nil {
			return e
		}
		b, e = s.encode(c)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE cases SET data=$1 WHERE ref=$2", b, ref); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) RotateKey(ctx context.Context, next *Crypto) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var marker []byte
		if e := tx.QueryRowContext(ctx, "SELECT key_check FROM deployment_secrets WHERE id=1 FOR UPDATE").Scan(&marker); e != nil {
			return e
		}
		if _, e := s.Crypto.Open(marker, "deployment"); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, "SELECT ref FROM cases")
		if e != nil {
			return e
		}
		var refs []string
		for rows.Next() {
			var r string
			if e = rows.Scan(&r); e != nil {
				rows.Close()
				return e
			}
			refs = append(refs, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, r := range refs {
			var b []byte
			if e = tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1", r).Scan(&b); e != nil {
				return e
			}
			var d diskCase
			if e = json.Unmarshal(b, &d); e != nil {
				return e
			}
			key, e := s.Crypto.Open(d.WrappedKey, "case-key:"+d.Case.ID)
			if e != nil {
				return e
			}
			d.WrappedKey = next.Seal(key, "case-key:"+d.Case.ID)
			b, e = json.Marshal(d)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE cases SET data=$1 WHERE ref=$2", b, r); e != nil {
				return e
			}
		}
		rows, e = tx.QueryContext(ctx, "SELECT id,case_ref FROM evidence")
		if e != nil {
			return e
		}
		type item struct {
			id, ref string
			b       []byte
		}
		var items []item
		for rows.Next() {
			var i item
			if e = rows.Scan(&i.id, &i.ref); e != nil {
				rows.Close()
				return e
			}
			items = append(items, i)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, i := range items {
			if e = tx.QueryRowContext(ctx, "SELECT encrypted FROM evidence WHERE id=$1", i.id).Scan(&i.b); e != nil {
				return e
			}
			var env envelope
			if e = json.Unmarshal(i.b, &env); e != nil {
				return e
			}
			id := "key:evidence:" + i.ref + ":" + i.id
			key, e := s.Crypto.Open(env.Key, id)
			if e != nil {
				return e
			}
			env.Key = next.Seal(key, id)
			b, _ := json.Marshal(env)
			if _, e = tx.ExecContext(ctx, "UPDATE evidence SET encrypted=$1 WHERE id=$2", b, i.id); e != nil {
				return e
			}
		}
		// Small credential/outbox values use master encryption and are re-encrypted atomically.
		for _, spec := range []struct{ table, column, prefix string }{{"users", "mfa_secret", "mfa:"}, {"notifications", "recipient", "notification:"}} {
			rows, e = tx.QueryContext(ctx, fmt.Sprintf("SELECT id,%s FROM %s WHERE %s IS NOT NULL", spec.column, spec.table, spec.column))
			if e != nil {
				return e
			}
			items = nil
			for rows.Next() {
				var i item
				if e = rows.Scan(&i.id, &i.b); e != nil {
					rows.Close()
					return e
				}
				items = append(items, i)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, i := range items {
				plain, e := s.Crypto.Open(i.b, spec.prefix+i.id)
				if e != nil {
					return e
				}
				if _, e = tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET %s=$1 WHERE id=$2", spec.table, spec.column), next.Seal(plain, spec.prefix+i.id), i.id); e != nil {
					return e
				}
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM sessions; DELETE FROM oidc_states"); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE deployment_secrets SET key_check=$1 WHERE id=1", next.Seal([]byte("beacon-key-check-v1"), "deployment")); e != nil {
			return e
		}
		return audit(ctx, tx, "operator", "encryption.rotated", "deployment", "All sessions revoked; retain prior backup keys")
	})
}
