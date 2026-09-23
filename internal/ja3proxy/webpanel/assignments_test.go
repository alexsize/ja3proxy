package webpanel

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

func TestDeviceAssignmentAPI(t *testing.T) {
	store, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := store.Create(device.Device{ID: "phone-017", Name: "Phone 017", ProxyUsername: "phone017", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Devices: store}.Handler()
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	w := deviceRequest(h, http.MethodPost, "/api/v1/device-assignments", map[string]any{
		"expected_version": 1,
		"assignment": map[string]any{
			"device_id": created.ID, "application": "Example", "version": "1.2.0", "valid_from": from,
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create assignment status = %d, body = %s", w.Code, w.Body.String())
	}
	var response struct {
		Assignment device.ApplicationAssignment `json:"assignment"`
		Registry   device.Registry              `json:"registry"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Assignment.ID == "" || response.Registry.ConfigVersion != 2 {
		t.Fatalf("create assignment response = %+v", response)
	}
	list := requestRecorder(h, "/api/v1/device-assignments")
	if list.Code != http.StatusOK || len(list.Body.Bytes()) == 0 {
		t.Fatalf("assignment list = %d %s", list.Code, list.Body.String())
	}
	w = deviceRequest(h, http.MethodPut, "/api/v1/device-assignments/"+response.Assignment.ID, map[string]any{
		"expected_version": 2,
		"assignment": map[string]any{
			"device_id": created.ID, "application": "Example", "version": "1.3.0", "valid_from": from,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update assignment status = %d, body = %s", w.Code, w.Body.String())
	}
	w = deviceRequest(h, http.MethodDelete, "/api/v1/device-assignments/"+response.Assignment.ID, map[string]any{"expected_version": 3})
	if w.Code != http.StatusOK {
		t.Fatalf("delete assignment status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := requestRecorder(h, "/api/v1/device-assignments/"+response.Assignment.ID); got.Code != http.StatusNotFound {
		t.Fatalf("deleted assignment status = %d", got.Code)
	}
}
