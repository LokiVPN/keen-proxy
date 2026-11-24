package ui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// deviceFormSnapshot binds the displayed MACs and effective modes to the
// config revision. Pending edits carry this same snapshot through rerenders.
func (p pages) deviceFormSnapshot(revision string, rows []deviceRow) string {
	modes := make(map[string]model.Mode, len(rows))
	for _, row := range rows {
		modes[row.MAC] = row.Mode
	}
	raw, _ := json.Marshal(modes) // Keys and values are strings.
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + base64.RawURLEncoding.EncodeToString(p.deviceFormMAC(revision, payload))
}

func (p pages) deviceFormMAC(revision, payload string) []byte {
	mac := hmac.New(sha256.New, []byte(p.deviceFormKey))
	mac.Write([]byte(revision))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func (p pages) readDeviceFormSnapshot(revision, snapshot string) (map[string]model.Mode, bool) {
	payload, proof, found := strings.Cut(snapshot, ".")
	if !found {
		return nil, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil || !hmac.Equal(signature, p.deviceFormMAC(revision, payload)) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	var modes map[string]model.Mode
	if err != nil || json.Unmarshal(raw, &modes) != nil {
		return nil, false
	}
	return modes, true
}

// parseDevicesDraft defaults every displayed row to off. Only its checked
// switch submits a mode. A full switch is valid only for a baseline full row.
func (p pages) parseDevicesDraft(form url.Values) (devicesDraft, bool) {
	newDevices, bulk, snapshot := form["new"], form["bulk"], form["displayed"]
	if len(snapshot) != 1 || len(newDevices) > 1 || (len(newDevices) == 1 && newDevices[0] != "1") || len(bulk) > 1 {
		return devicesDraft{}, false
	}
	displayed, ok := p.readDeviceFormSnapshot(form.Get("rev"), snapshot[0])
	if !ok {
		return devicesDraft{}, false
	}
	draft := devicesDraft{
		Modes: make(map[string]model.Mode, len(displayed)), Displayed: displayed,
		Snapshot: snapshot[0], NewDevices: len(newDevices) == 1,
	}
	if len(bulk) == 1 {
		draft.Bulk = model.Mode(bulk[0])
		if draft.Bulk != model.ModeSplit && draft.Bulk != model.ModeOff {
			return devicesDraft{}, false
		}
	}
	for mac := range displayed {
		draft.Modes[mac] = model.ModeOff
	}
	for _, mode := range []model.Mode{model.ModeSplit, model.ModeFull} {
		for _, raw := range form[string(mode)] {
			mac := deviceMAC(raw)
			if draft.Modes[mac] != model.ModeOff || (mode == model.ModeFull && displayed[mac] != model.ModeFull) {
				return devicesDraft{}, false
			}
			draft.Modes[mac] = mode
		}
	}
	return draft, true
}
