package webpanel

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

func TestApplicationCatalogAPI(t *testing.T) {
	store, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Devices: store}.Handler()
	w := deviceRequest(h, http.MethodPost, "/api/v1/applications", map[string]any{
		"expected_version": 0,
		"application":      map[string]any{"id": "example", "name": "Example", "platform": "iOS", "enabled": true},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create application status = %d, body = %s", w.Code, w.Body.String())
	}
	var response struct {
		Application device.Application `json:"application"`
		Registry    device.Registry    `json:"registry"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Application.ID != "example" || response.Registry.ConfigVersion != 1 {
		t.Fatalf("create application response = %+v", response)
	}
	if got := requestRecorder(h, "/api/v1/applications/example"); got.Code != http.StatusOK {
		t.Fatalf("get application status = %d", got.Code)
	}
	w = deviceRequest(h, http.MethodPut, "/api/v1/applications/example", map[string]any{
		"expected_version": 1,
		"application":      map[string]any{"name": "Example Updated", "platform": "iOS", "enabled": true},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update application status = %d, body = %s", w.Code, w.Body.String())
	}
	w = deviceRequest(h, http.MethodDelete, "/api/v1/applications/example", map[string]any{"expected_version": 2})
	if w.Code != http.StatusOK {
		t.Fatalf("delete application status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := requestRecorder(h, "/api/v1/applications/example"); got.Code != http.StatusNotFound {
		t.Fatalf("deleted application status = %d", got.Code)
	}
}
