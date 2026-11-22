package links

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestXHTTPSessionAliases(t *testing.T) {
	parse := func(q url.Values) (Outbound, error) {
		q.Set("type", "xhttp")
		return Parse("vless://11111111-2222-3333-4444-555555555555@node.example:443?" + q.Encode())
	}
	want, err := parse(url.Values{"extra": {`{"session_table":"abc123","session_length":"8-16"}`}})
	if err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]url.Values{
		"xray extra":      {"extra": {`{"sessionIDTable":"abc123","sessionIDLength":[8,16]}`}},
		"same extra":      {"extra": {`{"sessionIDTable":" abc123 ","session_table":"abc123","sessionIDLength":[8,16],"sessionLength":"8-16"}`}},
		"same query":      {"sessionIDTable": {" abc123 "}, "sessionTable": {"abc123"}, "sessionIDLength": {"8-16"}},
		"query and extra": {"sessionIDLength": {"8-16"}, "extra": {`{"sessionIDTable":"abc123","sessionLength":[8,16]}`}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parse(query)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("session alias options = %#v, error = %v, want %#v", got, err, want)
			}
		})
	}
	for name, query := range map[string]url.Values{
		"extra table":   {"extra": {`{"sessionIDTable":"abc123","session_table":"xyz789"}`}},
		"extra length":  {"extra": {`{"sessionIDLength":8,"sessionLength":16}`}},
		"query length":  {"sessionIDLength": {"8"}, "session_length": {"16"}},
		"same spelling": {"sessionIDLength": {"8", "16"}},
	} {
		t.Run("conflicting "+name, func(t *testing.T) {
			if _, err := parse(query); err == nil || !strings.Contains(err.Error(), "conflicting values for session") {
				t.Fatalf("wanted session alias conflict, got %v", err)
			}
		})
	}
}
