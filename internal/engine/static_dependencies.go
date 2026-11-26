package engine

import (
	"context"
	"reflect"
	"slices"

	"github.com/sagernet/sing-box/option"
)

// DeclaredGroupMembers reads a projected outbound with the runtime's option
// decoder. It returns the configured group list before any traffic walk.
func DeclaredGroupMembers(ctx context.Context, config []byte) []string {
	options, err := decodeOptions(ctx, config)
	if err != nil || len(options.Outbounds) != 1 {
		return nil
	}
	switch group := options.Outbounds[0].Options.(type) {
	case *option.SelectorOutboundOptions:
		return group.Outbounds
	case *option.URLTestOutboundOptions:
		return group.Outbounds
	default:
		return nil
	}
}

// ValidateStaticOutboundGraph checks the compiler's dependencies using only
// decoded option fields, without instantiating any profiles.
func ValidateStaticOutboundGraph(ctx context.Context, config []byte) error {
	graph, err := staticOutboundGraph(ctx, config)
	if err != nil {
		return err
	}
	return validateOutboundGraph(graph)
}

// StaticReserveChoices uses the graph compiled with direct as the edited
// reserve. Every affected failover selector currently ends at that sink.
// Substituting a candidate's active chain creates a cycle exactly when one
// of its members already reaches an affected selector.
func StaticReserveChoices(ctx context.Context, config []byte, affected, targets []string, activeChain func(string) []string) []string {
	graph, err := staticOutboundGraph(ctx, config)
	if err != nil || validateOutboundGraph(graph) != nil {
		return nil
	}
	dependents := outboundDependents(graph, affected)
	var choices []string
	for _, target := range targets {
		if !slices.ContainsFunc(activeChain(target), func(member string) bool { return dependents[member] }) {
			choices = append(choices, target)
		}
	}
	return choices
}

func outboundDependents(graph map[string][]string, roots []string) map[string]bool {
	incoming := make(map[string][]string, len(graph))
	for tag, deps := range graph {
		for _, dep := range deps {
			incoming[dep] = append(incoming[dep], tag)
		}
	}
	pending := slices.Clone(roots)
	seen := make(map[string]bool)
	for len(pending) > 0 {
		last := len(pending) - 1
		tag := pending[last]
		pending = pending[:last]
		if !seen[tag] {
			seen[tag] = true
			pending = append(pending, incoming[tag]...)
		}
	}
	return seen
}

func staticOutboundGraph(ctx context.Context, config []byte) (map[string][]string, error) {
	if err := validateRuntimeTags(config); err != nil {
		return nil, err
	}
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return nil, err
	}
	graph := make(map[string][]string, len(options.Outbounds)+len(options.Endpoints))
	for _, profile := range options.Outbounds {
		graph[profile.Tag] = staticOutboundReferences(profile.Options)
	}
	for _, profile := range options.Endpoints {
		graph[profile.Tag] = staticOutboundReferences(profile.Options)
	}
	return graph, nil
}

// independentDiagnosticLeaf also checks decoded references that a protocol
// may use outside its runtime startup dependency list.
func independentDiagnosticLeaf(ctx context.Context, config []byte, tag string) bool {
	options, err := decodeOptions(ctx, config)
	if err != nil {
		return false
	}
	for _, profile := range options.Outbounds {
		if profile.Tag == tag {
			return len(staticOutboundReferences(profile.Options)) == 0
		}
	}
	for _, profile := range options.Endpoints {
		if profile.Tag == tag {
			return len(staticOutboundReferences(profile.Options)) == 0
		}
	}
	return false
}

func staticOutboundReferences(options any) []string {
	var tags []string
	walkProfileOptions(reflect.ValueOf(options), func(value reflect.Value) bool {
		return visitOutboundReferences(value, func(tag string) bool {
			tags = append(tags, tag)
			return false
		})
	})
	return tags
}
