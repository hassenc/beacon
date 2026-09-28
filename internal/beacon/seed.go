package beacon

import (
	"context"
	"errors"
	"time"
)

// SeedDemo adds explicitly synthetic reports only to an empty deployment.
func SeedDemo(ctx context.Context, s *Store) error {
	users, e := s.Users(ctx)
	if e != nil {
		return e
	}
	var owner User
	for _, u := range users {
		if u.Role == "OWNER" {
			owner = u
			break
		}
	}
	if owner.ID == "" {
		return errors.New("Create an owner before seeding")
	}
	cs, e := s.Cases(ctx, owner)
	if e != nil {
		return e
	}
	if len(cs) > 0 {
		return errors.New("Demo seeding requires an empty case queue")
	}
	products := []Product{{ID: UUID(), Name: "Atlas Gateway", Family: "Industrial connectivity", Versions: "3.2.x, 3.3.x", Owner: "Platform security", Lifecycle: "SUPPORTED"}, {ID: UUID(), Name: "Beacon Edge Agent", Family: "Device software", Versions: "2.4.x", Owner: "Endpoint engineering", Lifecycle: "SUPPORTED"}, {ID: UUID(), Name: "Control Hub", Family: "Management console", Versions: "1.8.x", Owner: "Application security", Lifecycle: "SUPPORTED"}}
	for _, p := range products {
		if e = s.AddProduct(ctx, owner, p); e != nil {
			return e
		}
	}
	titles := []string{"Authentication bypass in gateway management API", "Path traversal in diagnostic bundle download", "Session persists after password change", "Excessive permissions on device configuration", "Information exposure in application error responses", "Unvalidated redirect in sign-in callback"}
	statuses := []string{"INVESTIGATING", "TRIAGE", "ACKNOWLEDGED", "REMEDIATING", "NEW", "RESOLVED"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "HIGH", "UNKNOWN", "LOW"}
	now := time.Now().UTC()
	for i, title := range titles {
		p := products[i%len(products)]
		c := Case{ID: UUID(), Ref: NewReference(), Title: title, Product: p.ID, ProductName: p.Name, AffectedVersion: p.Versions, Status: statuses[i], Severity: severities[i], Owner: owner.ID, Created: now.Add(-time.Duration(3+i*8) * time.Hour), Updated: now, Revision: 1, Payload: Payload{Description: "SYNTHETIC DEMO REPORT — not a real vulnerability.\n\nA researcher observed unexpected access behavior in the product's management interface while testing a local evaluation environment.", Steps: "1. Start an isolated test instance.\n2. Create a user with limited permissions.\n3. Request the affected management endpoint.\n4. Compare the response with the expected authorization policy.", Impact: "This synthetic scenario illustrates how unauthorized access could affect product configuration. No real systems or customer data were accessed.", ReporterName: "Demo researcher", Messages: []Message{{ID: "s_" + UUID(), At: now.Add(-time.Hour), Author: owner.Name, Visibility: "INTERNAL", Body: "Synthetic case for evaluating the response workflow. Confirm the affected versions before assigning remediation."}, {ID: "s_" + UUID(), At: now.Add(-30 * time.Minute), Author: owner.Name, Visibility: "REPORTER_VISIBLE", Body: "Thank you for your report. Our product security team is reviewing the reproduction steps."}}}}
		if i == 0 {
			c.CRA = &CRA{Classification: "VULNERABILITY", Awareness: now.Add(-17 * time.Hour), ConfirmedBy: owner.ID, Activated: now, Policy: DefaultPolicy()}
		}
		if i == 3 {
			c.CRA = &CRA{Classification: "INCIDENT", Awareness: now.Add(-30 * time.Hour), ConfirmedBy: owner.ID, Activated: now, Policy: DefaultPolicy(), Filings: []Filing{{Stage: "early", At: now.Add(-12 * time.Hour), Representative: "Demo representative", RecordedBy: owner.ID, RecordedAt: now, Reference: "SYNTHETIC-ONLY"}}}
		}
		if e = s.CreateCase(ctx, c, "BCN-RCVR-"+RandomHex(32)); e != nil {
			return e
		}
	}
	return s.Audit(ctx, owner.ID, "demo.seeded", "beacon", "Six synthetic cases; no reporter tokens retained")
}
