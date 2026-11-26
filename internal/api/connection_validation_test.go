package api

import (
	"encoding/base64"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestWireGuardKeyValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := func() *model.WireGuard {
		return &model.WireGuard{PrivateKey: key, Peer: model.WGPeer{PublicKey: key}}
	}
	for _, wg := range []*model.WireGuard{nil, valid(), {PrivateKey: key, Peer: model.WGPeer{PublicKey: key, PresharedKey: key}}} {
		if err := validateWGKeys(wg); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"private", "public", "preshared"} {
		wg := valid()
		switch field {
		case "private":
			wg.PrivateKey = "bad"
		case "public":
			wg.Peer.PublicKey = "bad"
		case "preshared":
			wg.Peer.PresharedKey = "bad"
		}
		if err := validateWGKeys(wg); err == nil {
			t.Fatalf("accepted invalid %s key", field)
		}
	}
	if validWGKey(base64.StdEncoding.EncodeToString(make([]byte, 31))) {
		t.Fatal("accepted short key")
	}
}
