package api

import (
	"encoding/json"
	"io"
	"net/http"
)

// decodeImportRequest reads a profile import request: one JSON value up to
// 2 MiB, room for an exported vpn:// URI, with unknown fields rejected.
func decodeImportRequest(w http.ResponseWriter, r *http.Request, v any) error {
	return decodeJSONRequest(w, r, 2<<20, v)
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}
