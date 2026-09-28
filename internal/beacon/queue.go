package beacon

import (
	"context"
	"encoding/json"
	"strings"
)

// Queue queries only authorized metadata and bounds every response to fifty cases.
func (s *Store) Queue(ctx context.Context, u User, query, status string, page int) ([]Case, int, error) {
	if u.ID == "" || u.Disabled {
		return nil, 0, nil
	}
	if page < 1 {
		page = 1
	}
	query = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(query, `\`, `\\`), "%", `\%`), "_", `\_`)
	where := ` FROM cases WHERE ($1 OR data->'Case'->>'Owner'=$2 OR (data->'Case'->'Watchers') ? $2) AND ($3='' OR data->'Case'->>'Status'=$3) AND concat_ws(' ',ref,data->'Case'->>'Title',data->'Case'->>'ProductName',data->'Case'->>'AffectedVersion',data->'Case'->'Assessment'->>'CVE',data->'Case'->'Assessment'->>'CWE') ILIKE $4`
	all := u.Role == "OWNER" || u.Role == "TRIAGE" || u.Role == "VIEWER"
	var total int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*)"+where, all, u.ID, status, "%"+query+"%").Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT data->'Case'"+where+" ORDER BY data->'Case'->>'Created' DESC,ref DESC LIMIT 50 OFFSET $5", all, u.ID, status, "%"+query+"%", (page-1)*50)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	var out []Case
	for rows.Next() {
		var b []byte
		var c Case
		if e = rows.Scan(&b); e != nil {
			return nil, 0, e
		}
		if e = json.Unmarshal(b, &c); e != nil {
			return nil, 0, e
		}
		if CanRead(u, c) {
			out = append(out, c)
		}
	}
	return out, total, rows.Err()
}
