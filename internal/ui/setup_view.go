package ui

import (
	"cmp"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// setupPage carries the link only for a retry in the failed check response.
type setupPage struct {
	Rev, Input, Error, Warning string
	CheckPath, ConfirmPath     string
	CancelPath, SourceTitle    string
	SourceID                   string
	Managing                   bool
	Replacing, KeepRouting     bool
	EvaluateRules              bool
	Result                     *setupResult
}

type setupResult struct {
	Title, Chip, Message, AccountURL           string
	SourceID                                   string
	Active, HasRouting                         bool
	Token, Expiry, Traffic, Servers            string
	Announce, RouteName, RouteHint, RulesState string
	Actions                                    []setupAction
}

type setupAction struct {
	Name, Sites, IP string
}

func (p pages) renderSetup(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, page setupPage) {
	data := p.opts.pageData(r)
	data.Title = "KeenProxy"
	data.SignedIn = true
	data.ViewOnly = p.role(r) == RoleView
	flow := setupFlowFor(r)
	page.CheckPath, page.ConfirmPath, page.CancelPath = flow.path+"/check", flow.path+"/confirm", "/connections"
	page.Managing = flow.path != setupPath
	page.Replacing = flow.replaceID != ""
	page.KeepRouting = page.Managing
	if page.Managing {
		data.ActiveTab = "/connections"
	} else {
		page.ConfirmPath = setupPath + "/enable"
		page.CancelPath = setupPath
	}
	if cfg != nil {
		i := flow.replacement(cfg)
		if flow.replaceID == "" || i >= 0 {
			page.Rev = Revision(cfg)
		}
		page.Replacing = page.Replacing || i >= 0
		page.KeepRouting = !flow.initialRouting(cfg)
		if i >= 0 {
			source := appliedSubscriptionFor(p.deps.Subscriptions(), cfg.Subscriptions[i].ID)
			page.SourceID, page.SourceTitle = source.ID, cmp.Or(source.Metadata.Title, data.Text["overview_subscription"])
		}
		if !page.Managing && page.KeepRouting {
			page.CancelPath = "/"
		}
	}
	switch {
	case page.Replacing:
		data.Title = data.Text["setup_replace"]
	case page.KeepRouting:
		data.Title = data.Text["setup_add"]
	}
	if page.Rev == "" && page.Error == "" {
		page.Error = data.Text["setup_unavailable"]
	}
	data.Setup = &page
	render(w, r, status, "setup", data)
}

// setupResultFor turns provider metadata into facts and fixed state messages.
// Network and unusable-response errors are shown beside the link field.
func setupResultFor(preview SetupPreview, now, expiry time.Time, lang string) *setupResult {
	text := translations[lang]
	metadata := preview.Metadata
	result := &setupResult{Title: metadata.Title, AccountURL: metadata.ProfileURL}
	switch {
	case preview.State == subscription.StateHWIDLimit:
		result.Chip = text["setup_limit"]
		result.Message = text["setup_limit_hint"]
	case !expiry.IsZero() && !expiry.After(now):
		result.Chip = text["setup_expired"]
		result.Message = fmt.Sprintf(text["setup_expired_hint"], setupDate(expiry, text))
	case preview.State == subscription.StateReady && preview.NodeCount > 0:
		result.Active = true
		result.Chip = text["setup_active"]
		result.Announce = metadata.Announce
		result.Expiry = setupRemaining(expiry, now, lang)
		result.Traffic = setupTraffic(metadata.Usage, lang)
		result.Servers = fmt.Sprint(preview.NodeCount)
		if len(preview.NodeNames) > 0 {
			result.Servers += ": " + strings.Join(preview.NodeNames, ", ")
			if preview.NodeCount > len(preview.NodeNames) {
				result.Servers += " …"
			}
		}
		result.addRouting(preview, text)
	default:
		return nil
	}
	return result
}

func (r *setupResult) addRouting(preview SetupPreview, text map[string]string) {
	switch preview.RulesState {
	case "pending":
		r.RulesState = text["setup_rules_pending"]
	case "withheld":
		r.RulesState = text["setup_rules_withheld"]
	case "failed":
		r.RulesState = text["setup_rules_malformed"]
	}
	if preview.Routing == nil {
		return
	}
	r.RouteName = preview.Routing.Name
	r.HasRouting = true
	r.RouteHint = text["setup_profile_direct"]
	if preview.Routing.GlobalProxy {
		r.RouteHint = text["setup_profile_vpn"]
	}
	for _, action := range []struct {
		name string
		list subscription.RoutingActionSummary
	}{
		{text["setup_action_direct"], preview.Routing.Direct},
		{text["setup_action_proxy"], preview.Routing.Proxy},
		{text["setup_action_block"], preview.Routing.Block},
	} {
		if action.list.Sites.Count+action.list.IP.Count > 0 {
			r.Actions = append(r.Actions, setupAction{
				Name: action.name, Sites: setupList(action.list.Sites, text["setup_sites_count"]),
				IP: setupList(action.list.IP, text["setup_ip_count"]),
			})
		}
	}
}

func setupList(list subscription.RoutingListSummary, format string) string {
	count := fmt.Sprintf(format, list.Count)
	if len(list.Categories) == 0 {
		return count
	}
	count += " · " + strings.Join(list.Categories, ", ")
	if list.More {
		count += " …"
	}
	return count
}

func setupExpiry(usage *subscription.Usage) time.Time {
	if usage != nil && usage.Expire > 0 {
		return time.Unix(usage.Expire, 0)
	}
	return time.Time{}
}

func setupDate(date time.Time, text map[string]string) string {
	month := text["setup_month_"+strings.ToLower(date.Month().String())]
	return fmt.Sprintf(text["setup_date"], month, date.Day(), date.Year())
}

func setupRemaining(expiry, now time.Time, lang string) string {
	if expiry.IsZero() {
		return ""
	}
	text := translations[lang]
	days := int(math.Ceil(expiry.Sub(now).Hours() / 24))
	key := "setup_days_many"
	if lang == "ru" {
		if digit := days % 100; digit < 11 || digit > 14 {
			switch days % 10 {
			case 1:
				key = "setup_days_one"
			case 2, 3, 4:
				key = "setup_days_few"
			}
		}
	} else if days == 1 {
		key = "setup_days_one"
	}
	return setupDate(expiry, text) + ", " + fmt.Sprintf(text[key], days)
}

func setupTraffic(usage *subscription.Usage, lang string) string {
	if usage == nil {
		return ""
	}
	text := translations[lang]
	used := float64(usage.Upload) + float64(usage.Download)
	if usage.Total > 0 {
		display := "0"
		if used > 0 {
			display = setupBytes(used, lang)
		}
		return fmt.Sprintf(text["setup_traffic_total"], display, setupBytes(float64(usage.Total), lang))
	}
	if used > 0 {
		return fmt.Sprintf(text["setup_traffic_used"], setupBytes(used, lang))
	}
	return ""
}

func setupBytes(value float64, lang string) string {
	units := []string{"setup_bytes", "setup_kb", "setup_mb", "setup_gb", "setup_tb"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	number := strings.TrimSuffix(fmt.Sprintf("%.1f", value), ".0")
	if lang == "ru" {
		number = strings.Replace(number, ".", ",", 1)
	}
	return fmt.Sprintf(translations[lang][units[unit]], number)
}
