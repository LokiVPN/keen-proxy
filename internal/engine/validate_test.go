package engine

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestValidateSchemaWithoutStartingEngine(t *testing.T) {
	if err := Validate(context.Background(), []byte(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{`, `{"outbounds":[{"type":"unknown"}]}`, `{"outbounds":[{"type":"shadowsocks","server":"203.0.113.1","server_port":443,"method":"invalid-method","password":"example"}]}`} {
		if err := Validate(context.Background(), []byte(raw)); err == nil {
			t.Fatalf("accepted invalid schema: %s", raw)
		}
	}
}

func TestValidateReleasesEndpointsOnConstructorError(t *testing.T) {
	const config = `{
		"log":{"disabled":true},
		"endpoints":[{"type":"wireguard","tag":"wg","address":["192.0.2.2/32"],
			"private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
			"peers":[{"address":"198.51.100.2","port":51820,"allowed_ips":["0.0.0.0/0"],
				"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}]}],
		"outbounds":[{"type":"shadowsocks","server":"203.0.113.1","server_port":443,
			"method":"invalid-method","password":"example"}]
	}`
	before := runtime.NumGoroutine()
	for range 3 {
		err := ValidateRuntimeProfiles(t.Context(), []byte(config))
		if err == nil || !strings.Contains(err.Error(), "initialize outbound") {
			t.Fatalf("expected a failure constructing the outbound after the endpoint, got %v", err)
		}
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("failed validation retained %d endpoint goroutines", after-before)
	}
}
