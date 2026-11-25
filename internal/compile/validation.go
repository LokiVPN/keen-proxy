package compile

import (
	"encoding/json"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// ConnectionValidationConfig contains only profiles and a local resolver: no
// listeners, rule-set files, firewall, routes from imported configs or services.
func ConnectionValidationConfig(cfg *model.Config) ([]byte, error) {
	profiles, err := connections(cfg)
	if err != nil {
		return nil, err
	}
	return validationConfig(profiles.outbounds, profiles.endpoints)
}

// ConnectionSettingsConfig compiles the runtime profile graph without
// materializing network policies or DNS and provider rule-set files.
func ConnectionSettingsConfig(in Input) ([]byte, error) {
	profiles, err := connections(in.Config)
	if err != nil {
		return nil, err
	}
	chains, tags := failover(in.Config)
	managed, err := compileSubscriptions(in, tags)
	if err != nil {
		return nil, err
	}
	return validationConfig(runtimeOutbounds(in.Config, profiles.outbounds, chains, tags, managed), profiles.endpoints)
}

// RuntimeValidationConfig projects the compiled runtime's outbound graph
// onto a validation instance without listeners or on-disk rule-set readers.
func RuntimeValidationConfig(out Output) ([]byte, error) {
	var profiles struct {
		Outbounds json.RawMessage
		Endpoints json.RawMessage
	}
	if err := json.Unmarshal(out.SingBox, &profiles); err != nil {
		return nil, err
	}
	return validationConfig(profiles.Outbounds, profiles.Endpoints)
}

func validationConfig(outbounds, endpoints any) ([]byte, error) {
	return json.Marshal(obj{
		"log":       obj{"disabled": true},
		"dns":       obj{"servers": []obj{{"type": "local", "tag": "validation-dns"}}},
		"route":     obj{"default_domain_resolver": "validation-dns"},
		"outbounds": outbounds, "endpoints": endpoints,
	})
}
