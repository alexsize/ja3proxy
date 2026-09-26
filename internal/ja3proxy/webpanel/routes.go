package webpanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
)

type routeTestRequest struct {
	Phase       routing.Phase `json:"phase"`
	Host        string        `json:"host"`
	SNI         string        `json:"sni"`
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	DeviceID    string        `json:"device_id"`
	DeviceTags  []string      `json:"device_tags"`
	Username    string        `json:"username"`
	ALPN        []string      `json:"alpn"`
	TLSVersions []uint16      `json:"tls_versions"`
	JA3         string        `json:"ja3"`
	JA3Hash     string        `json:"ja3_hash"`
	JA4         string        `json:"ja4"`
}

func (panel Server) routeTest(w http.ResponseWriter, request *http.Request) {
	if panel.Routes == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "route manager is unavailable")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 16<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input routeTestRequest
	if err := decoder.Decode(&input); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid route test: %v", err))
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeAPIError(w, http.StatusBadRequest, "request must contain one JSON object")
		return
	}
	if input.Phase == "" {
		input.Phase = routing.PhasePreTLS
	}
	if input.Phase != routing.PhasePreTLS && input.Phase != routing.PhasePostClientHello {
		writeAPIError(w, http.StatusBadRequest, "phase must be PRE_TLS or POST_CLIENTHELLO")
		return
	}
	if input.Port < 0 || input.Port > 65535 {
		writeAPIError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}
	var ip netip.Addr
	if strings.TrimSpace(input.IP) != "" {
		parsed, err := netip.ParseAddr(strings.TrimSpace(input.IP))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "ip must be a valid address")
			return
		}
		ip = parsed
	}
	decision := panel.Routes.Resolve(input.Phase, routing.Request{
		Host: input.Host, SNI: input.SNI, IP: ip, Port: input.Port,
		DeviceID: input.DeviceID, DeviceTags: input.DeviceTags, Username: input.Username,
		ALPN: input.ALPN, TLSVersions: input.TLSVersions, JA3: input.JA3, JA3Hash: input.JA3Hash, JA4: input.JA4,
	})
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		return
	}
}
