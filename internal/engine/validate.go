package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

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

func validateProfiles(ctx context.Context, config []byte, runtimeGraph bool) error {
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{Context: Context(ctx), Options: options})
	if err != nil {
		return err
	}
	if runtimeGraph {
		return errors.Join(validateRuntimeDependencies(instance), instance.Close())
	}
	return instance.Close()
}

// Check generated tags before the core decoder can return a raw error.
func validateRuntimeTags(config []byte) error {
	type tagged struct{ Tag string }
	var graph struct{ Outbounds, Endpoints []tagged }
	if err := json.Unmarshal(config, &graph); err != nil {
		return err
	}
	tags := make(map[string]bool, len(graph.Outbounds)+len(graph.Endpoints))
	for _, profiles := range [][]tagged{graph.Outbounds, graph.Endpoints} {
		for _, profile := range profiles {
			if tags[profile.Tag] {
				return model.ErrConnectionTagConflict
			}
			tags[profile.Tag] = true
		}
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
