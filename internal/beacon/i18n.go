package beacon

import (
	"encoding/json"
	"net/http"
	"strings"
)

var french = func() map[string]string {
	b, _ := webFS.ReadFile("web/fr.json")
	var m map[string]string
	if e := json.Unmarshal(b, &m); e != nil {
		panic(e)
	}
	return m
}()

func translate(s, lang string) string {
	if lang == "fr" {
		if v, ok := french[s]; ok {
			return v
		}
	}
	return s
}
func language(r *http.Request) string {
	if q := r.URL.Query().Get("lang"); q == "en" || q == "fr" {
		return q
	}
	if c, e := r.Cookie("beacon_language"); e == nil && (c.Value == "en" || c.Value == "fr") {
		return c.Value
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "fr") {
		return "fr"
	}
	return "en"
}
func localizedLabel(s, lang string) string {
	if lang == "fr" {
		if v, ok := map[string]string{"NEW": "nouveau", "ACKNOWLEDGED": "accusé réception", "TRIAGE": "qualification", "INVESTIGATING": "investigation", "REMEDIATING": "correction", "DISCLOSURE_PENDING": "divulgation en attente", "RESOLVED": "résolu", "CLOSED": "clôturé", "DUPLICATE": "doublon", "NOT_REPRODUCIBLE": "non reproductible", "OUT_OF_SCOPE": "hors périmètre", "REJECTED": "rejeté", "UNKNOWN": "inconnu", "LOW": "faible", "MEDIUM": "moyenne", "HIGH": "élevée", "CRITICAL": "critique", "OWNER": "propriétaire", "ENGINEER": "ingénieur", "VIEWER": "observateur", "SUPPORTED": "pris en charge", "MAINTENANCE": "maintenance", "END_OF_LIFE": "fin de vie"}[s]; ok {
			return v
		}
	}
	return strings.ReplaceAll(strings.ToLower(s), "_", " ")
}
