package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDatAppearsAfterAnEarlierMiss(t *testing.T) {
	dir := t.TempDir()
	handler := datHandler(dir)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		return response
	}
	if got := get("/data/retry.dat").Code; got != http.StatusNotFound {
		t.Fatalf("missing dat returned HTTP %d", got)
	}
	payload := "synthetic dat payload"
	if err := os.WriteFile(filepath.Join(dir, "retry.dat"), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	response := get("/data/retry.dat")
	if response.Code != http.StatusOK || response.Body.String() != payload ||
		response.Header().Get("Content-Length") != strconv.Itoa(len(payload)) {
		t.Fatalf("unexpected dat response: %d, %v, %q", response.Code, response.Header(), response.Body)
	}
	if got := get("/data/").Code; got != http.StatusNotFound {
		t.Fatalf("dat directory returned HTTP %d", got)
	}
}
