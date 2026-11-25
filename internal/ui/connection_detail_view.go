package ui

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

type connectionDetailPage struct {
	Path, Fragment, Rev, Name        string
	Enabled, CanProbe, Reveal, Dirty bool
	RevealURL, Reserve, ReserveHint  string
	ReserveTiming                    string
	Options                          []connectionOption
	Chain                            []connectionChainMember
	Facts, Parameters                []connectionDetailField
	References                       []connectionReference
	TrafficGroup                     bool
}

type connectionChainMember struct {
	Name, URL string
	Disabled  bool
}

type connectionDetailField struct {
	Label, Value string
	Masked, Raw  bool
}

type connectionReference struct {
	Label, URL string
}

type connectionHealthView struct {
	Status overviewChip
	Detail string
}

type connectionHostsView struct {
	Path, ToggleURL, ToggleLabel string
	Rows                         []connectionHostView
}

type connectionHostView struct {
	Name, Received, Sent string
}

func (p pages) renderConnectionDetail(w http.ResponseWriter, r *http.Request, code int, cfg *model.Config, draft *model.Connection, message string, guard []connectionReference) {
	i := connectionIndex(cfg, connectionIDFromSegment(r.PathValue("id")))
	if i < 0 {
		switch {
		case message != "":
			p.renderPage(w, r, code, localized(r)["nav_connections"], message)
		case cfg == nil:
			p.renderPage(w, r, http.StatusServiceUnavailable, localized(r)["nav_connections"], "setup_unavailable")
		default:
			p.notFound(w, r)
		}
		return
	}
	conn := cfg.Connections[i]
	data := p.opts.pageData(r)
	data.Title, data.SignedIn = cmp.Or(conn.Name, conn.ID), true
	data.ViewOnly = p.role(r) == RoleView
	if r.Method == http.MethodPost && code == http.StatusOK {
		data.Flash = data.Text[message]
	} else {
		data.Message, data.Flash = data.Text[message], takeFlash(w, r, data.Text)
	}
	reveal := p.role(r) == RoleManage && r.Method == http.MethodGet && r.URL.Query().Get("reveal") == "1"
	allHosts := r.URL.Query().Get("hosts") == "all"
	health, _ := p.deps.ConnectionHealth(conn.ID)
	data.ConnectionHealth = detailHealth(health, data.Text)
	active := -1
	if health.TrafficGroup {
		data.ConnectionTrafficLinks = detailTrafficLinks(cfg, health.TrafficMembers)
	} else {
		var series []stats.Point
		active, series = p.deps.ConnectionTraffic(conn.ID)
		data.ConnectionHosts = p.detailHosts(conn.ID, allHosts, data.Lang)
		data.Traffic = trafficChart(series, time.Now(), data.Lang, "detail_chart_label")
	}
	data.ConnectionDetail = p.makeConnectionDetail(r.Context(), cfg, i, draft, health, active, reveal, allHosts, guard, data.Text)
	render(w, r, code, "connection-detail", data)
}

func (p pages) makeConnectionDetail(ctx context.Context, cfg *model.Config, index int, draft *model.Connection, health ConnectionHealth, active int, reveal, allHosts bool, guard []connectionReference, text map[string]string) *connectionDetailPage {
	conn := cfg.Connections[index]
	settings := conn
	if draft != nil {
		settings = *draft
	}
	name := cmp.Or(conn.Name, conn.ID)
	var refs []connectionReference
	if len(guard) == 0 {
		refs = connectionReferences(cfg, conn.ID, text)
	}
	profile := connectionimport.ConnectionFacts(conn)
	return &connectionDetailPage{
		Path: connectionDetailPath(conn.ID), Fragment: connectionDetailFragmentPath(conn.ID), Rev: Revision(cfg),
		Name: name, Enabled: !settings.Disabled, CanProbe: !conn.Disabled, Reveal: reveal,
		Dirty:     settings.Disabled != conn.Disabled || settings.Fallback != conn.Fallback,
		RevealURL: detailURL(conn.ID, !reveal, allHosts, "connection-parameters"),
		Reserve:   connectionIDSegment(settings.Fallback), ReserveHint: fmt.Sprintf(text["detail_reserve_hint"], name),
		ReserveTiming: fmt.Sprintf(text["detail_reserve_timing"], cfg.Failover.DownAfter, cfg.Failover.UpAfter),
		Options:       p.detailFallbackOptions(ctx, cfg, index, settings, text),
		Chain:         detailChain(cfg, settings, text),
		Facts:         detailFacts(profile, health.Class, active, refs, text),
		Parameters:    detailParameters(conn, profile, reveal, text), References: guard,
		TrafficGroup: health.TrafficGroup,
	}
}

func connectionDetailFragmentPath(id string) string {
	return "/fragments/connection/" + connectionIDSegment(id)
}

// Only known UI flags are carried across links. Displayed secrets never
// appear in a URL, form field or fragment.
func detailURL(id string, reveal, allHosts bool, anchor string) string {
	query := make(url.Values)
	if reveal {
		query.Set("reveal", "1")
	}
	if allHosts {
		query.Set("hosts", "all")
	}
	path := connectionDetailPath(id)
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return path + "#" + anchor
}

func (p pages) detailFallbackOptions(ctx context.Context, cfg *model.Config, index int, settings model.Connection, text map[string]string) []connectionOption {
	targets := cfg.ConnectionFallbackTargets(settings.ID)
	labels := manualReserveLabels(cfg, text)
	labels[""] = text["detail_reserve_none"]
	candidate := *cfg
	candidate.Connections = slices.Clone(cfg.Connections)
	candidate.Connections[index] = settings
	options := make([]connectionOption, 0, len(targets))
	for _, target := range targets {
		candidate.Connections[index].Fallback = target
		invalid := p.deps.ValidateConnectionSettings(ctx, &candidate) != nil
		if !invalid || target == settings.Fallback {
			options = append(options, connectionOption{Target: connectionIDSegment(target), Label: labels[target], Disabled: invalid})
		}
	}
	return options
}

func detailTrafficLinks(cfg *model.Config, members []string) []connectionReference {
	var links []connectionReference
	if cfg != nil {
		for _, tag := range members {
			if name := connectionName(cfg, tag); name != "" {
				links = append(links, connectionReference{Label: name, URL: connectionDetailPath(tag)})
			}
		}
	}
	return links
}

// detailChain includes the edited profile first, then the configured chain of
// its reserve. Disabled members stay visible because their reserves still apply.
func detailChain(cfg *model.Config, conn model.Connection, text map[string]string) []connectionChainMember {
	chain := []connectionChainMember{{Name: cmp.Or(conn.Name, conn.ID), Disabled: conn.Disabled}}
	if conn.Fallback == "" {
		return chain
	}
	for _, id := range cfg.Chain(conn.Fallback) {
		if id == model.TargetDirect {
			chain = append(chain, connectionChainMember{Name: text["connections_direct"]})
		} else if i := connectionIndex(cfg, id); i >= 0 {
			c := cfg.Connections[i]
			chain = append(chain, connectionChainMember{Name: cmp.Or(c.Name, id), URL: connectionDetailPath(id), Disabled: c.Disabled})
		}
	}
	return chain
}

func detailHealth(health ConnectionHealth, text map[string]string) connectionHealthView {
	if health.Disabled {
		return connectionHealthView{Status: overviewChip{Label: text["overview_connection_disabled"]}}
	}
	if health.Checked.IsZero() {
		return connectionHealthView{Status: overviewChip{Label: text["overview_not_checked"]}}
	}
	checked := fmt.Sprintf(text["detail_checked_at"], health.Checked.Local().Format("15:04"))
	if !health.Available {
		return connectionHealthView{Status: overviewChip{Label: text["overview_no_response"], Class: "warn"}, Detail: checked}
	}
	protocol := "HTTP"
	if health.HTTPS {
		protocol = "HTTPS"
	}
	return connectionHealthView{
		Status: overviewChip{Label: text["detail_responding"], Class: "ok"},
		Detail: protocol + " " + fmt.Sprintf(text["overview_latency"], health.LatencyMS) + " · " + checked,
	}
}

func detailFacts(profile connectionimport.Facts, class stats.TargetClass, active int, refs []connectionReference, text map[string]string) []connectionDetailField {
	fact := func(key, value string) connectionDetailField {
		return connectionDetailField{Label: text[key], Value: value}
	}
	hidden := text["wizard_summary_hidden"]
	protocol := profile.Protocol
	if profile.Security != "" {
		protocol += " · " + profile.Security
	}
	if profile.RoutingType != "" {
		protocol = text["detail_type_"+profile.RoutingType]
	}
	if profile.TypeHidden {
		protocol = hidden
	}
	rows := []connectionDetailField{fact("wizard_type", protocol)}
	if profile.ServerHidden {
		profile.Server = hidden
	}
	if profile.SNIHidden {
		profile.SNI = hidden
	}
	if profile.TransportHidden {
		profile.Transport = hidden
	}
	if profile.Server != "" {
		rows = append(rows, fact("wizard_field_server", profile.Server))
	}
	if profile.SNI != "" {
		rows = append(rows, fact("wizard_field_sni", profile.SNI))
	}
	if profile.Transport != "" {
		rows = append(rows, fact("detail_transport", profile.Transport))
	}
	classKey := map[stats.TargetClass]string{
		stats.TargetDirect: "connections_direct", stats.TargetVPN: "detail_vpn",
		stats.TargetMixed: "detail_follow_connection", stats.TargetBlock: "detail_blocked",
	}[class]
	if classKey != "" {
		rows = append(rows, fact("detail_routing", text[classKey]))
	}
	var uses []string
	for _, ref := range refs {
		uses = append(uses, ref.Label)
	}
	if len(uses) > 0 {
		rows = append(rows, fact("detail_used_by", strings.Join(uses, " · ")))
	}
	if active >= 0 {
		rows = append(rows, fact("detail_active", strconv.Itoa(active)))
	}
	return rows
}

func detailParameters(conn model.Connection, facts connectionimport.Facts, reveal bool, text map[string]string) []connectionDetailField {
	var fields []connectionDetailField
	add := func(key, value string, secret, raw bool) {
		if secret && !reveal {
			fields = append(fields, connectionDetailField{Label: text[key], Masked: true})
		} else if value != "" {
			fields = append(fields, connectionDetailField{Label: text[key], Value: value, Raw: raw})
		}
	}
	addresses := strings.Join(facts.Addresses, ", ")
	if conn.Type == model.ConnWireGuard && conn.WireGuard != nil {
		wg := conn.WireGuard
		add("wizard_field_privateKey", wg.PrivateKey, true, false)
		add("wizard_field_address", addresses, false, false)
		add("wizard_field_endpoint", facts.Server, false, false)
		add("wizard_field_peerKey", wg.Peer.PublicKey, true, false)
		if wg.Peer.PresharedKey != "" {
			add("wizard_field_psk", wg.Peer.PresharedKey, true, false)
		}
		return fields
	}
	add("wizard_field_address", addresses, false, false)
	var raw string
	if reveal {
		raw = connectionParameterText(conn)
	}
	add("detail_profile", raw, true, true)
	return fields
}

func connectionParameterText(conn model.Connection) string {
	switch conn.Type {
	case model.ConnLink:
		return conn.Link
	case model.ConnAmneziaWG:
		return conn.AmneziaWG
	case model.ConnTrustTunnel:
		if conn.TrustTunnel != nil {
			return conn.TrustTunnel.Link
		}
		return conn.Link
	case model.ConnSingBox:
		profile := conn.Outbound
		if conn.Endpoint != nil {
			profile = conn.Endpoint
		}
		encoded, err := json.MarshalIndent(profile, "", "  ")
		if err == nil {
			return string(encoded)
		}
	}
	return ""
}

func (p pages) detailHosts(id string, all bool, lang string) connectionHostsView {
	const previewCount = 5
	view := connectionHostsView{Path: connectionDetailFragmentPath(id) + "/hosts"}
	limit := previewCount
	if all {
		limit = stats.MaxHosts
		view.Path += "?hosts=all"
	}
	hosts, total := p.deps.ConnectionHosts(id, limit)
	if total > previewCount {
		text := translations[lang]
		view.ToggleURL = detailURL(id, false, !all, "connection-hosts")
		view.ToggleLabel = text["detail_hosts_less"]
		if !all {
			view.ToggleLabel = fmt.Sprintf(text["detail_hosts_all"], total)
		}
	}
	view.Rows = make([]connectionHostView, 0, len(hosts))
	for _, host := range hosts {
		view.Rows = append(view.Rows, connectionHostView{
			Name: host.Host, Received: setupBytes(float64(host.Down), lang), Sent: setupBytes(float64(host.Up), lang),
		})
	}
	return view
}

// connectionReferences covers every top-level connection consumer, including
// settings that remain in older or hand-edited configurations.
func connectionReferences(cfg *model.Config, id string, text map[string]string) []connectionReference {
	var refs []connectionReference
	add := func(key, value, path string) {
		label := text[key]
		if value != "" {
			label = fmt.Sprintf(label, value)
		}
		refs = append(refs, connectionReference{Label: label, URL: path})
	}
	home := homeNetwork(cfg)
	for i := range cfg.Networks {
		n := &cfg.Networks[i]
		name := cmp.Or(n.Name, n.CIDR)
		if n.Target == id {
			if n == home {
				add("detail_ref_main", name, "/")
			} else {
				add("detail_ref_network", name, "")
			}
		}
		if n.Default == id {
			add("detail_ref_default", name, "")
		}
	}
	for _, group := range cfg.Groups {
		if group.Target == id {
			path := ""
			if group.Name == "own-vpn" {
				path = "/routing"
			}
			add("detail_ref_group", cmp.Or(group.Name, text["detail_unnamed"]), path)
		}
	}
	for _, conn := range cfg.Connections {
		if conn.ID != id && conn.Fallback == id {
			add("detail_ref_reserve", cmp.Or(conn.Name, conn.ID), connectionDetailPath(conn.ID))
		}
	}
	for _, source := range cfg.Subscriptions {
		if source.Fallback == id {
			add("detail_ref_subscription", source.ID, "/connections")
		}
	}
	for _, client := range cfg.Clients {
		if client.Target == id {
			add("detail_ref_client", cmp.Or(client.Name, client.MAC), "")
		}
	}
	if cfg.DNS.Connection == id {
		add("detail_ref_dns", "", "")
	}
	return refs
}

func appendProfileReferences(refs []connectionReference, ids []string, cfg *model.Config, text map[string]string) []connectionReference {
	for _, id := range ids {
		label := fmt.Sprintf(text["detail_ref_profile"], cmp.Or(connectionName(cfg, id), id))
		refs = append(refs, connectionReference{Label: label, URL: connectionDetailPath(id)})
	}
	return refs
}
