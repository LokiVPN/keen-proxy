package compile

import (
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestDisabledPresetHasNoDNSOrRouting(t *testing.T) {
	c := &model.Config{Groups: []model.Group{{Name: "installed but off", Target: "direct", Disabled: true, Entries: []string{"example.com"}}}}
	c.Defaults()
	if names := NewDNSNames(c, nil); len(DomainNames(c)) != 0 || names.Observed("example.com") || len(names.RuleSets(nil)) != 0 {
		t.Fatal("disabled preset participates in DNS")
	}
	sets, block, routed, _ := groupRuleSets(c.Groups, t.TempDir(), nil)
	if len(sets)+len(block)+len(routed) != 0 {
		t.Fatal("disabled preset compiled")
	}
	c.Groups[0].Disabled = false
	if len(DomainNames(c)) != 1 {
		t.Fatal("enabled preset missing")
	}
}
