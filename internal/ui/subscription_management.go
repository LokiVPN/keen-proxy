package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	subscriptionPathPrefix     = "/connections/subscriptions/"
	subscriptionNewPath        = subscriptionPathPrefix + "new"
	subscriptionReplacePattern = subscriptionPathPrefix + "{id}/replace"
)

// ErrProfileReferenceUncertain reports that a profile possibly referencing
// the specific target uses options this build cannot inspect.
var ErrProfileReferenceUncertain = errors.New("could not inspect a possible saved profile reference")

func subscriptionPath(id string) string {
	return subscriptionPathPrefix + url.PathEscape(id)
}

func subscriptionIndex(cfg *model.Config, id string) int {
	return slices.IndexFunc(cfg.Subscriptions, func(source subscription.Source) bool { return source.ID == id })
}

// newSubscriptionID keeps both the source ID and its managed target namespace
// free of collisions with saved or compiled connections and dormant references.
func (p pages) newSubscriptionID(ctx context.Context, cfg *model.Config) (string, error) {
	occupied, err := p.occupiedRoutingIDs(cfg)
	if err != nil {
		return "", err
	}
	namespaces := make(map[string]bool)
	for tag := range occupied {
		if id, _, ok := model.ParseManagedTarget(tag); ok {
			namespaces[id] = true
		}
	}
	for number := 2; ; number++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		id := "sub" + strconv.Itoa(number)
		if occupied[id] || namespaces[id] {
			continue
		}
		refs, err := p.deps.SubscriptionProfileReferences(ctx, cfg, id)
		if errors.Is(err, ErrProfileReferenceUncertain) {
			continue
		}
		if err != nil {
			return "", err
		}
		if len(refs) == 0 {
			return id, nil
		}
	}
}

func (p pages) subscriptionRemove(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, setupFormSize)
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
		return
	}
	id := r.PathValue("id")
	i := subscriptionIndex(cfg, id)
	if i == -1 {
		p.notFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	text := localized(r)
	refs := routingTargetReferences(cfg, text, "", func(target string) bool {
		source, _, ok := model.ParseManagedTarget(target)
		return ok && source == id
	})
	if cfg.ProviderRules != nil && cfg.ProviderRules.Source == id {
		refs = append(refs, connectionReference{Label: text["connections_ref_provider_rules"], URL: "/routing"})
	}
	profiles, err := p.deps.SubscriptionProfileReferences(ctx, cfg, id)
	refs = appendProfileReferences(refs, profiles, cfg, text)
	if err != nil {
		p.renderConnectionsResult(w, r, http.StatusUnprocessableEntity, cfg, nil, fmt.Sprintf(text["connections_remove_reference_error"], id), refs)
		return
	}
	if len(refs) > 0 {
		p.renderConnectionsResult(w, r, http.StatusConflict, cfg, nil, fmt.Sprintf(text["connections_remove_referenced"], id), refs)
		return
	}

	// Apply handles the runtime catalog and snapshot for the reduced source set.
	rev := r.PostForm.Get("rev")
	cfg.Subscriptions = slices.Delete(cfg.Subscriptions, i, i+1)
	err = p.deps.Apply(ctx, cfg, rev)
	if err == nil {
		redirectWithFlash(w, r, "/connections", "flash_subscription_removed")
		return
	}
	current := p.deps.Config()
	var unsaved *model.AppliedUnsavedError
	switch {
	case errors.As(err, &unsaved):
		p.renderConnections(w, r, http.StatusInternalServerError, current, nil, "apply_not_saved")
	case errors.Is(err, model.ErrConfigChanged), Revision(current) != rev:
		p.renderConnections(w, r, http.StatusConflict, current, nil, "revision_changed")
	default:
		p.renderConnections(w, r, http.StatusUnprocessableEntity, current, nil, "overview_apply_error")
	}
}
