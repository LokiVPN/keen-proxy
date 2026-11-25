package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Validate checks schemas and constructors without starting listeners, polling,
// external clients or network connections. The caller supplies profiles only.
func Validate(ctx context.Context, config []byte) error {
	return validateProfiles(ctx, config, false)
}

// ValidateRuntimeProfiles also checks the complete graph from the compiler.
// Dependency resolution in sing-box normally happens only during Start.
func ValidateRuntimeProfiles(ctx context.Context, config []byte) error {
	if err := validateRuntimeTags(config); err != nil {
		return err
	}
	return validateProfiles(ctx, config, true)
}

func validateProfiles(ctx context.Context, config []byte, runtimeGraph bool) (err error) {
	ctx = Context(service.ExtendContext(ctx))
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return err
	}
	registry := &validationEndpoints{EndpointRegistry: service.FromContext[adapter.EndpointRegistry](ctx)}
	ctx = service.ContextWith[adapter.EndpointRegistry](ctx, registry)
	defer func() { err = errors.Join(err, registry.close()) }()
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return err
	}
	if runtimeGraph {
		return errors.Join(validateRuntimeDependencies(instance), instance.Close())
	}
	return instance.Close()
}

// validationEndpoints owns the stacks allocated by WireGuard and AmneziaWG
// constructors. An unstarted box has not registered the endpoint cleanups,
// and a partially constructed box may fail before returning an instance.
type validationEndpoints struct {
	adapter.EndpointRegistry
	stacks []adapter.Endpoint
}

func (r *validationEndpoints) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag, kind string, options any) (adapter.Endpoint, error) {
	endpoint, err := r.EndpointRegistry.Create(ctx, router, logger, tag, kind, options)
	if err == nil && kind == C.TypeWireGuard {
		r.stacks = append(r.stacks, endpoint)
	}
	return endpoint, err
}

func (r *validationEndpoints) close() error {
	var err error
	for _, endpoint := range r.stacks {
		err = errors.Join(err, common.Close(endpoint))
	}
	return err
}

// RuntimeOutboundTags returns the configured and generated tags consumed by
// the outbound manager at Start.
func RuntimeOutboundTags(raw []byte) ([]string, error) {
	type tagged struct{ Tag string }
	var graph struct{ Outbounds, Endpoints []tagged }
	if err := json.Unmarshal(raw, &graph); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(graph.Outbounds)+len(graph.Endpoints))
	for _, profiles := range [][]tagged{graph.Outbounds, graph.Endpoints} {
		for _, profile := range profiles {
			tags = append(tags, profile.Tag)
		}
	}
	return tags, nil
}

// Check generated tags before the core decoder can return a raw error.
func validateRuntimeTags(config []byte) error {
	tags, err := RuntimeOutboundTags(config)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if seen[tag] {
			return model.ErrConnectionTagConflict
		}
		seen[tag] = true
	}
	return nil
}

// validateRuntimeDependencies uses the constructors' dependency lists, the
// same edges sing-box orders at startup.
func validateRuntimeDependencies(instance *box.Box) error {
	graph := make(map[string][]string)
	for _, outbound := range instance.Outbound().Outbounds() {
		graph[outbound.Tag()] = outbound.Dependencies()
	}
	for _, endpoint := range instance.Endpoint().Endpoints() {
		graph[endpoint.Tag()] = endpoint.Dependencies()
	}
	return validateOutboundGraph(graph)
}

func validateOutboundGraph(graph map[string][]string) error {
	type visitState uint8
	const (
		visiting visitState = iota + 1
		complete
	)
	states := make(map[string]visitState, len(graph))
	var visit func(string) error
	visit = func(tag string) error {
		switch states[tag] {
		case complete:
			return nil
		case visiting:
			return errors.New("circular runtime outbound dependency")
		}
		deps, ok := graph[tag]
		if !ok {
			return errors.New("missing runtime outbound dependency")
		}
		states[tag] = visiting
		for _, dep := range deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		states[tag] = complete
		return nil
	}
	for tag := range graph {
		if err := visit(tag); err != nil {
			return err
		}
	}
	return nil
}

func decodeOptions(ctx context.Context, config []byte) (option.Options, error) {
	ctx = Context(ctx)
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return option.Options{}, err
	}
	if err := rejectEndpointJunk(options); err != nil {
		return option.Options{}, err
	}
	return options, nil
}

// rejectEndpointJunk runs after the core decoder has folded field names into
// WireGuardEndpointOptions. A parallel raw-map check misses JC/JMIN/JMAX.
func rejectEndpointJunk(options option.Options) error {
	for _, endpoint := range options.Endpoints {
		wg, ok := endpoint.Options.(*option.WireGuardEndpointOptions)
		if !ok || wg == nil {
			continue
		}
		if err := awg.DeviceJunkBudget(uint64(wg.Jc), uint64(wg.Jmin), uint64(wg.Jmax)); err != nil {
			return fmt.Errorf("endpoint %q: %w", endpoint.Tag, err)
		}
	}
	return nil
}
