package beacon

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type AffectedProduct struct{ ProductID, Name, Versions, Component string }
type Assessment struct{ CVE, CWE, CVSSVector, CVSSScore, Exploitation, Remediation string }
type ExternalReference struct{ Label, URL string }
type AwarenessChange struct {
	Before, After time.Time
	Actor, Reason string
	At            time.Time
}
type Packet struct {
	FormatVersion, Organization, CaseReference, Title string
	Affected                                          []AffectedProduct
	Assessment                                        Assessment
	Description, Steps, Impact                        string
	CRA                                               *CRA
	Checklist                                         []string
	Generated                                         time.Time
}

func BuildPacket(c Case, org string) Packet {
	cra := c.CRA
	if cra != nil {
		copyCRA := *cra
		copyCRA.ConfirmedBy = ""
		copyCRA.Changes = nil
		copyCRA.Filings = append([]Filing(nil), cra.Filings...)
		for i := range copyCRA.Filings {
			copyCRA.Filings[i].Notes = ""
			copyCRA.Filings[i].RecordedBy = ""
		}
		cra = &copyCRA
	}
	affected := append([]AffectedProduct(nil), c.Affected...)
	if c.ProductName != "" {
		found := false
		for _, p := range affected {
			if p.Name == c.ProductName && p.Versions == c.AffectedVersion {
				found = true
			}
		}
		if !found {
			affected = append([]AffectedProduct{{ProductID: c.Product, Name: c.ProductName, Versions: c.AffectedVersion}}, affected...)
		}
	}
	return Packet{"1", org, c.Ref, c.Title, affected, c.Assessment, c.Payload.Description, c.Payload.Steps, c.Payload.Impact, cra, []string{"Confirm legal manufacturer and assigned representative in SRP", "Review affected countries and product identification", "Verify awareness, severity, impact and mitigation", "Review selected attachments for unnecessary personal data", "File manually through SRP; record receipt in Beacon"}, time.Now().UTC()}
}
func (a *App) packetPage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	c, e := a.Store.Case(r.Context(), r.PathValue("ref"))
	if e != nil || !CanManage(u) {
		a.fail(w, r, 404, "Case not found")
		return
	}
	if c.CRA == nil {
		a.fail(w, r, 400, "Activate CRA tracking first")
		return
	}
	b, e := json.MarshalIndent(BuildPacket(c, a.Config.Organization), "", "  ")
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "packet", Page{Title: "CRA packet review", User: u, Case: c, PacketJSON: string(b)})
}
func (a *App) packetExport(w http.ResponseWriter, r *http.Request, u User, c Case) {
	if !CanManage(u) || c.CRA == nil || r.FormValue("confirm") != "yes" || parseRevision(r) != c.Revision {
		a.fail(w, r, 400, "Review and confirm the current case revision first")
		return
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	b, _ := json.MarshalIndent(BuildPacket(c, a.Config.Organization), "", "  ")
	f, e := z.Create("packet.json")
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	f.Write(b)
	manifest := ""
	seen := map[string]bool{}
	for _, id := range r.Form["evidence"] {
		if seen[id] {
			continue
		}
		seen[id] = true
		found := false
		for _, file := range c.Payload.Attachments {
			if file.ID == id {
				found = true
				content, e := a.Store.Evidence(r.Context(), c.Ref, id)
				if e != nil {
					a.storageError(w, r, e)
					return
				}
				f, e := z.Create("evidence/" + id)
				if e != nil {
					a.storageError(w, r, e)
					return
				}
				f.Write(content)
				manifest += file.SHA256 + "  evidence/" + id + "\n"
			}
		}
		if !found {
			a.fail(w, r, 400, "Selected evidence is not in this case")
			return
		}
	}
	f, e = z.Create("SHA256SUMS")
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	f.Write([]byte(Hash(string(b)) + "  packet.json\n" + manifest))
	if e = z.Close(); e != nil {
		a.storageError(w, r, e)
		return
	}
	if e = a.Store.Audit(r.Context(), u.ID, "cra.packet.exported", c.Ref, fmt.Sprintf("revision %d; %d explicitly selected files", c.Revision, len(seen))); e != nil {
		a.storageError(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+c.Ref+`-cra.zip"`)
	w.Write(buf.Bytes())
}
func (a *App) extraAction(r *http.Request, actor User, c *Case, action string) error {
	if !CanManage(actor) {
		return errors.New("Owner/Triage access required")
	}
	switch action {
	case "watchers":
		if len(r.Form["watcher"]) > 50 {
			return errors.New("watcher limit reached")
		}
		var ids []string
		for _, id := range r.Form["watcher"] {
			user, e := a.Store.User(r.Context(), id)
			if e != nil || user.Disabled {
				return errors.New("invalid watcher")
			}
			if !Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		c.Watchers = ids
	case "assessment":
		x := Assessment{strings.TrimSpace(r.FormValue("cve")), strings.TrimSpace(r.FormValue("cwe")), strings.TrimSpace(r.FormValue("vector")), strings.TrimSpace(r.FormValue("score")), r.FormValue("exploitation"), strings.TrimSpace(r.FormValue("remediation"))}
		if x.CVE != "" && !regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`).MatchString(x.CVE) {
			return errors.New("invalid CVE identifier")
		}
		if x.CWE != "" && !regexp.MustCompile(`^CWE-[0-9]+$`).MatchString(x.CWE) {
			return errors.New("invalid CWE identifier")
		}
		if x.CVSSScore != "" {
			v, e := strconv.ParseFloat(x.CVSSScore, 64)
			if e != nil || v < 0 || v > 10 || strings.ContainsAny(strings.ToLower(x.CVSSScore), "nai") {
				return errors.New("CVSS score must be 0 through 10")
			}
		}
		if len(x.CVSSVector) > 300 || len(x.Remediation) > 2000 || !Contains([]string{"UNKNOWN", "SUSPECTED", "OBSERVED", "NOT_OBSERVED"}, x.Exploitation) {
			return errors.New("invalid assessment")
		}
		c.Assessment = x
	case "affected":
		if len(c.Affected) >= 50 {
			return errors.New("affected product limit reached")
		}
		name, e := field(r, "product_name", 200)
		if e != nil {
			return e
		}
		versions, e := field(r, "versions", 300)
		if e != nil {
			return e
		}
		component := strings.TrimSpace(r.FormValue("component"))
		if len(component) > 200 {
			return errors.New("component too long")
		}
		c.Affected = append(c.Affected, AffectedProduct{Name: name, Versions: versions, Component: component})
	case "duplicate":
		ref := strings.TrimSpace(r.FormValue("duplicate"))
		if ref == c.Ref {
			return errors.New("cannot duplicate a case to itself")
		}
		if len(ref) > 100 || !strings.HasPrefix(ref, "BCN-") {
			return errors.New("invalid duplicate case reference")
		}
		c.DuplicateOf = ref
		c.Status = "DUPLICATE"
	case "reference":
		if len(c.References) >= 30 {
			return errors.New("reference limit reached")
		}
		label, e := field(r, "label", 100)
		if e != nil {
			return e
		}
		v := r.FormValue("url")
		parsed, e := url.Parse(v)
		if e != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || len(v) > 2000 {
			return errors.New("reference must be an HTTPS URL without credentials")
		}
		c.References = append(c.References, ExternalReference{label, v})
	case "awareness":
		if c.CRA == nil {
			return errors.New("CRA tracking is not active")
		}
		reason, e := field(r, "reason", 1000)
		if e != nil {
			return e
		}
		at, e := parseTime(r.FormValue("awareness"))
		if e != nil || at.After(time.Now()) || at.Before(time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)) {
			return errors.New("invalid awareness timestamp")
		}
		for _, f := range c.CRA.Filings {
			if at.After(f.At) {
				return errors.New("awareness cannot be after a recorded filing")
			}
		}
		if r.FormValue("confirm") != "yes" {
			return errors.New("confirm awareness correction")
		}
		if len(c.CRA.Changes) >= 100 {
			return errors.New("awareness correction limit reached")
		}
		c.CRA.Changes = append(c.CRA.Changes, AwarenessChange{c.CRA.Awareness, at, actor.ID, reason, time.Now().UTC()})
		c.CRA.Awareness = at
	case "hold":
		reason, e := field(r, "reason", 1000)
		if e != nil {
			return e
		}
		c.LegalHold = r.FormValue("hold") == "yes"
		c.HoldReason = reason
	default:
		return errors.New("unknown workflow action")
	}
	return nil
}
func (s *Store) PurgeCase(ctx context.Context, u User, ref string, revision int, reason string) error {
	if len(strings.TrimSpace(reason)) < 10 || len(reason) > 1000 {
		return errors.New("owner and a documented reason are required")
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, u.ID)
		if e != nil {
			return e
		}
		if e = validateActor(u, current); e != nil {
			return e
		}
		if current.Role != "OWNER" {
			return errors.New("owner and a documented reason are required")
		}
		var b []byte
		if e := tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&b); e != nil {
			return e
		}
		c, e := s.decode(b)
		if e != nil {
			return e
		}
		if c.LegalHold || !TerminalStatus(c.Status) || c.Revision != revision {
			return errors.New("purge requires a terminal case, current revision and no legal hold")
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM sessions WHERE case_ref=$1", ref); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM notifications WHERE case_ref=$1", ref); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM cases WHERE ref=$1", ref); e != nil {
			return e
		}
		return audit(ctx, tx, current.ID, "case.purged", ref, reason)
	})
}
