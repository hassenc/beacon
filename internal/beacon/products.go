package beacon

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *App) productEdit(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	e := a.Store.transaction(r.Context(), func(tx *sql.Tx) error {
		current, e := lockUser(r.Context(), tx, u.ID)
		if e != nil {
			return e
		}
		if e = validateActor(u, current); e != nil {
			return e
		}
		if !CanManage(current) {
			return errors.New("Owner/Triage access required")
		}
		var raw []byte
		if e := tx.QueryRowContext(r.Context(), "SELECT data FROM products WHERE id=$1 FOR UPDATE", r.PathValue("id")).Scan(&raw); e != nil {
			return e
		}
		var p Product
		if e := json.Unmarshal(raw, &p); e != nil {
			return e
		}
		if p.Revision != parseRevision(r) {
			return errors.New("Product changed; reload before saving")
		}
		if r.FormValue("action") == "version" {
			if len(p.Releases) >= 200 {
				return errors.New("version limit reached")
			}
			v := ProductVersion{strings.TrimSpace(r.FormValue("version")), r.FormValue("released"), r.FormValue("support"), r.FormValue("end")}
			if v.Version == "" || len(v.Version) > 200 || !Contains([]string{"UNKNOWN", "SUPPORTED", "MAINTENANCE", "END_OF_LIFE"}, v.Support) {
				return errors.New("invalid version")
			}
			for _, date := range []string{v.Released, v.EndOfSupport} {
				if date != "" {
					if _, e := time.Parse("2006-01-02", date); e != nil {
						return errors.New("invalid date")
					}
				}
			}
			for _, old := range p.Releases {
				if old.Version == v.Version {
					return errors.New("version already exists")
				}
			}
			p.Releases = append(p.Releases, v)
		} else {
			for _, f := range []struct {
				k string
				v *string
			}{{"identifier", &p.Identifier}, {"description", &p.Description}, {"support_end", &p.SupportEnd}, {"repository", &p.RepositoryURL}, {"documentation", &p.DocumentationURL}} {
				value := strings.TrimSpace(r.FormValue(f.k))
				if len(value) > 2000 {
					return errors.New("field too long")
				}
				*f.v = value
			}
			for _, v := range []string{p.RepositoryURL, p.DocumentationURL} {
				if v != "" {
					link, e := url.Parse(v)
					if e != nil || link.Scheme != "https" || link.Host == "" || link.User != nil {
						return errors.New("use HTTPS URLs without credentials")
					}
				}
			}
			if p.SupportEnd != "" {
				if _, e := time.Parse("2006-01-02", p.SupportEnd); e != nil {
					return errors.New("invalid support end date")
				}
			}
			p.Lifecycle = r.FormValue("lifecycle")
			if !Contains([]string{"SUPPORTED", "MAINTENANCE", "END_OF_LIFE"}, p.Lifecycle) {
				return errors.New("invalid lifecycle")
			}
		}
		p.Revision++
		raw, e = json.Marshal(p)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(r.Context(), "UPDATE products SET data=$1 WHERE id=$2", raw, p.ID); e != nil {
			return e
		}
		return audit(r.Context(), tx, current.ID, "product.updated", p.ID, "")
	})
	if e != nil {
		a.fail(w, r, 400, "Product update failed: "+e.Error())
		return
	}
	http.Redirect(w, r, "/app/products", 303)
}
