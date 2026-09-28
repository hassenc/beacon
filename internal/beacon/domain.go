package beacon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const Version = "0.1.0-beta.1"

var Statuses = []string{"NEW", "ACKNOWLEDGED", "TRIAGE", "INVESTIGATING", "REMEDIATING", "DISCLOSURE_PENDING", "RESOLVED", "CLOSED", "DUPLICATE", "NOT_REPRODUCIBLE", "OUT_OF_SCOPE", "REJECTED"}
var Severities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
var Roles = []string{"OWNER", "TRIAGE", "ENGINEER", "VIEWER"}

type User struct {
	ID          string
	Name        string
	Email       string
	Role        string
	Password    string `json:"-"`
	Disabled    bool
	MFAEnabled  bool
	OIDCSubject string
	// AuthGeneration changes whenever credentials or identity authority changes.
	// Sessions are bound to the generation observed during authentication.
	AuthGeneration int64
}
type ProductVersion struct{ Version, Released, Support, EndOfSupport string }
type Product struct {
	Revision                                                             int
	Identifier, Description, SupportEnd, RepositoryURL, DocumentationURL string
	Releases                                                             []ProductVersion
	ID                                                                   string
	Name                                                                 string
	Family                                                               string
	Versions                                                             string
	Owner                                                                string
	Lifecycle                                                            string
}
type Message struct {
	ID         string
	At         time.Time
	Author     string
	Visibility string
	Body       string
}
type Attachment struct {
	ID         string
	Name       string
	SHA256     string
	Data       []byte
	Size       int
	At         time.Time
	Visibility string
	Scan       string
}
type Payload struct {
	Description  string
	Steps        string
	Impact       string
	ReporterName string
	Email        string
	Messages     []Message
	Attachments  []Attachment
}
type Case struct {
	Watchers        []string
	ID              string
	Ref             string
	Title           string
	Product         string
	ProductName     string
	AffectedVersion string
	Status          string
	Severity        string
	Owner           string
	Created         time.Time
	Updated         time.Time
	Revision        int
	TokenHash       string `json:"-"`
	Payload         Payload
	CRA             *CRA
	Affected        []AffectedProduct
	Assessment      Assessment
	DuplicateOf     string
	References      []ExternalReference
	LegalHold       bool
	HoldReason      string
}
type Policy struct {
	Version           string
	EarlyHours        int
	NotificationHours int
	FinalDays         int
	IncidentMonths    int
	Source            string
}
type Filing struct {
	Stage          string
	At             time.Time
	Representative string
	Reference      string
	Notes          string
	RecordedBy     string
	RecordedAt     time.Time
}
type CRA struct {
	Classification string
	Awareness      time.Time
	ConfirmedBy    string
	Activated      time.Time
	Policy         Policy
	CorrectiveAt   *time.Time
	Filings        []Filing
	Changes        []AwarenessChange
}
type Deadline struct {
	Stage     string
	Label     string
	Due       *time.Time
	Submitted *time.Time
	State     string
	Remaining string
}
type AuditEvent struct {
	Sequence int64
	At       time.Time
	Actor    string
	Action   string
	Object   string
	Metadata string
	Previous string
	Hash     string
}

type PublicCase struct {
	Ref         string
	Title       string
	Product     string
	Version     string
	Status      string
	Created     time.Time
	Description string
	Steps       string
	Impact      string
	Messages    []Message
	Attachments []Attachment
}

func Public(c Case) PublicCase {
	p := PublicCase{Ref: c.Ref, Title: c.Title, Product: c.ProductName, Version: c.AffectedVersion, Status: ExternalStatus(c.Status), Created: c.Created, Description: c.Payload.Description, Steps: c.Payload.Steps, Impact: c.Payload.Impact}
	for _, m := range c.Payload.Messages {
		if m.Visibility == "REPORTER_VISIBLE" {
			m.Author = "Product security team"
			if len(m.ID) > 2 && m.ID[:2] == "r_" {
				m.Author = "Reporter"
			}
			p.Messages = append(p.Messages, m)
		}
	}
	for _, a := range c.Payload.Attachments {
		if a.Visibility == "REPORTER_VISIBLE" {
			a.Data = nil
			p.Attachments = append(p.Attachments, a)
		}
	}
	return p
}
func ExternalStatus(s string) string {
	switch s {
	case "NEW":
		return "Received"
	case "ACKNOWLEDGED", "TRIAGE", "INVESTIGATING":
		return "Under review"
	case "REMEDIATING", "DISCLOSURE_PENDING":
		return "Fix in progress"
	case "RESOLVED":
		return "Resolved"
	default:
		return "Closed"
	}
}
func TerminalStatus(s string) bool {
	return Contains([]string{"CLOSED", "RESOLVED", "DUPLICATE", "NOT_REPRODUCIBLE", "OUT_OF_SCOPE", "REJECTED"}, s)
}
func CanRead(u User, c Case) bool {
	return !u.Disabled && u.ID != "" && (u.Role == "OWNER" || u.Role == "TRIAGE" || u.Role == "VIEWER" || (u.Role == "ENGINEER" && (c.Owner == u.ID || Contains(c.Watchers, u.ID))))
}
func CanManage(u User) bool {
	return !u.Disabled && u.ID != "" && (u.Role == "OWNER" || u.Role == "TRIAGE")
}
func CanWrite(u User, c Case) bool {
	return !u.Disabled && u.ID != "" && (CanManage(u) || (u.Role == "ENGINEER" && (c.Owner == u.ID || Contains(c.Watchers, u.ID))))
}
func Contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func RandomHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }
func UUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	ms := time.Now().UnixMilli()
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	b[6] = (b[6] & 15) | 112
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func NewReference() string { return fmt.Sprintf("BCN-%d-%s", time.Now().UTC().Year(), RandomHex(5)) }
func Transition(from, to string) bool {
	if from == to {
		return true
	}
	next := map[string]string{"NEW": "ACKNOWLEDGED", "ACKNOWLEDGED": "TRIAGE", "TRIAGE": "INVESTIGATING", "INVESTIGATING": "REMEDIATING", "REMEDIATING": "DISCLOSURE_PENDING", "DISCLOSURE_PENDING": "RESOLVED", "RESOLVED": "CLOSED"}
	if next[from] == to {
		return true
	}
	return next[from] != "" && Contains([]string{"DUPLICATE", "NOT_REPRODUCIBLE", "OUT_OF_SCOPE", "REJECTED"}, to)
}
func CalendarMonths(t time.Time, n int) time.Time {
	t = t.UTC()
	first := time.Date(t.Year(), t.Month()+time.Month(n), 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	last := first.AddDate(0, 1, -1).Day()
	d := t.Day()
	if d > last {
		d = last
	}
	return first.AddDate(0, 0, d-1)
}
func Deadlines(c *CRA, now time.Time) []Deadline {
	if c == nil {
		return nil
	}
	early := c.Awareness.Add(time.Duration(c.Policy.EarlyHours) * time.Hour)
	notice := c.Awareness.Add(time.Duration(c.Policy.NotificationHours) * time.Hour)
	ds := []Deadline{{Stage: "early", Label: fmt.Sprintf("%dh · Early warning", c.Policy.EarlyHours), Due: &early}, {Stage: "notification", Label: fmt.Sprintf("%dh · Notification", c.Policy.NotificationHours), Due: &notice}, {Stage: "final", Label: "Final report"}}
	if c.Classification == "VULNERABILITY" && c.CorrectiveAt != nil {
		d := c.CorrectiveAt.AddDate(0, 0, c.Policy.FinalDays)
		ds[2].Due = &d
	}
	for _, f := range c.Filings {
		if f.Stage == "notification" && c.Classification == "INCIDENT" {
			d := CalendarMonths(f.At, c.Policy.IncidentMonths)
			ds[2].Due = &d
		}
	}
	for i := range ds {
		d := &ds[i]
		d.State = "WAITING FOR TRIGGER"
		d.Remaining = "Awaiting recorded trigger"
		for _, f := range c.Filings {
			if f.Stage == d.Stage {
				at := f.At
				d.Submitted = &at
				d.State = "SUBMITTED"
				d.Remaining = "Recorded filing"
				if d.Due != nil && at.After(*d.Due) {
					d.State = "SUBMITTED LATE"
				}
				break
			}
		}
		if d.Submitted != nil || d.Due == nil {
			continue
		}
		left := d.Due.Sub(now)
		d.State = "OPEN"
		if left <= 0 {
			d.State = "OVERDUE"
			left = -left
		}
		d.Remaining = fmt.Sprintf("%dd %02dh %02dm", int(left.Hours())/24, int(left.Hours())%24, int(left.Minutes())%60)
	}
	return ds
}
func (c *CRA) AddFiling(f Filing, now time.Time) error {
	if len(c.Filings) >= 100 {
		return errors.New("filing record limit reached")
	}
	if !Contains([]string{"early", "notification", "final", "intermediate"}, f.Stage) || f.Representative == "" || f.At.IsZero() || f.At.After(now) || f.At.Before(c.Awareness) {
		return errors.New("Enter a valid filing time at or after awareness, no later than now, and a representative")
	}
	for _, old := range c.Filings {
		if old.Stage == f.Stage && f.Stage != "intermediate" {
			return errors.New("This stage already has a recorded filing")
		}
	}
	ds := Deadlines(c, now)
	for _, d := range ds {
		if d.Stage == f.Stage && d.Due == nil {
			return errors.New("Record the final-report trigger first")
		}
	}
	if f.Stage == "final" {
		trigger := c.CorrectiveAt
		if c.Classification == "INCIDENT" {
			for _, old := range c.Filings {
				if old.Stage == "notification" {
					t := old.At
					trigger = &t
				}
			}
		}
		if trigger != nil && f.At.Before(*trigger) {
			return errors.New("Final filing cannot precede its trigger")
		}
	}
	c.Filings = append(c.Filings, f)
	return nil
}
