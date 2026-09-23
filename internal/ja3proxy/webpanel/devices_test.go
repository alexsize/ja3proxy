package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

func deviceRequest(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:10000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDeviceManagerAPI(t *testing.T) {
	store, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	h := Server{Devices: store}.Handler()
	w := deviceRequest(h, http.MethodPost, "/api/v1/devices", map[string]any{
		"expected_version": 0,
		"device":           map[string]any{"name": "iPhone 017", "proxy_username": "iphone017", "enabled": true},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", w.Code, w.Body.String())
	}
	var created struct {
		Device   device.Device   `json:"device"`
		Registry device.Registry `json:"registry"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Device.ID == "" || created.Registry.ConfigVersion != 1 {
		t.Fatalf("create response = %+v", created)
	}
	item := requestRecorder(h, "/api/v1/devices/"+created.Device.ID)
	if item.Code != http.StatusOK || !bytes.Contains(item.Body.Bytes(), []byte("iPhone 017")) {
		t.Fatalf("get response = %d %s", item.Code, item.Body.String())
	}
	w = deviceRequest(h, http.MethodPut, "/api/v1/devices/"+created.Device.ID, map[string]any{
		"expected_version": 1,
		"device":           map[string]any{"name": "iPhone 017 updated", "proxy_username": "iphone017", "enabled": true},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", w.Code, w.Body.String())
	}
	w = deviceRequest(h, http.MethodPut, "/api/v1/devices/"+created.Device.ID, map[string]any{
		"expected_version": 1,
		"device":           map[string]any{"name": "stale", "enabled": true},
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d, body = %s", w.Code, w.Body.String())
	}
	w = deviceRequest(h, http.MethodDelete, "/api/v1/devices/"+created.Device.ID, map[string]any{"expected_version": 2})
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := requestRecorder(h, "/api/v1/devices/"+created.Device.ID); got.Code != http.StatusNotFound {
		t.Fatalf("deleted device status = %d", got.Code)
	}
}
