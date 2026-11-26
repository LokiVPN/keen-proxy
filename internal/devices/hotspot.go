package devices

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	keeneticHotspotURL = "http://127.0.0.1:79/rci/show/ip/hotspot"
	hotspotBodyLimit   = 1 << 20
)

// The router endpoint is local. Use a dedicated transport without proxy
// discovery and refuse redirects to keep each lookup on the fixed endpoint.
var hotspotClient = &http.Client{
	Timeout: 500 * time.Millisecond,
	Transport: &http.Transport{
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func keeneticHotspot(ctx context.Context) map[string]string {
	return readKeeneticHotspot(ctx, keeneticHotspotURL)
}

// readKeeneticHotspot returns only valid display names keyed by canonical MAC.
// A failed or incomplete response leaves name discovery to the other sources.
func readKeeneticHotspot(ctx context.Context, endpoint string) map[string]string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	response, err := hotspotClient.Do(req)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, hotspotBodyLimit+1))
	if err != nil || len(body) > hotspotBodyLimit {
		return nil
	}
	var hotspot struct {
		Hosts []struct {
			MAC      string `json:"mac"`
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
		} `json:"host"`
	}
	if json.Unmarshal(body, &hotspot) != nil {
		return nil
	}
	names := make(map[string]string)
	for _, host := range hotspot.Hosts {
		mac, err := net.ParseMAC(host.MAC)
		if err != nil {
			continue
		}
		key := mac.String()
		if name := cleanAssignedName(host.Name); name != "" {
			names[key] = name
		} else if hostname := cleanName(host.Hostname); hostname != "" && names[key] == "" {
			names[key] = hostname
		}
	}
	return names
}

// An assigned display name may contain spaces. Reject controls before
// normalizing whitespace so a line break cannot become part of a name.
func cleanAssignedName(name string) string {
	if strings.ContainsFunc(name, unicode.IsControl) {
		return ""
	}
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || name == "*" || utf8.RuneCountInString(name) > 64 {
		return ""
	}
	return name
}
