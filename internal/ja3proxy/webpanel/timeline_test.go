package webpanel

import (
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func TestFingerprintTimelineMarksChangesAndAppliesFilters(t *testing.T) {
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	observations := []recorder.Observation{
		{ID: "second", CapturedAt: base.Add(time.Minute), Meta: recorder.Meta{ResolvedDeviceID: "phone-017", Application: "Example", ApplicationVersion: "2"}, Fingerprints: &tlshello.Fingerprints{JA3: "b", JA3Hash: "hash-b", JA4: "ja4-b"}},
		{ID: "first", CapturedAt: base, Meta: recorder.Meta{ResolvedDeviceID: "phone-017", Application: "Example", ApplicationVersion: "1"}, Fingerprints: &tlshello.Fingerprints{JA3: "a", JA3Hash: "hash-a", JA4: "ja4-a"}},
		{ID: "ignored", CapturedAt: base, Meta: recorder.Meta{ResolvedDeviceID: "other", Application: "Example"}, Fingerprints: &tlshello.Fingerprints{JA3: "z", JA4: "ja4-z"}},
	}
	filtered := filteredObservations(observations, observationFilter{DeviceID: "phone-017", Application: "Example"})
	points := buildFingerprintTimeline(filtered)
	if len(points) != 2 || points[0].ObservationID != "first" || !points[0].Changed || !points[1].Changed {
		t.Fatalf("timeline = %+v", points)
	}
	if len(filteredObservations(observations, observationFilter{ApplicationVersion: "missing"})) != 0 {
		t.Fatal("application version filter matched an unrelated observation")
	}
	if !strings.Contains(points[1].ApplicationVersion, "2") {
		t.Fatalf("timeline version = %+v", points[1])
	}
}
