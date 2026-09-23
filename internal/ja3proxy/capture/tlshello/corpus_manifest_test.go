package tlshello

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestClientHelloCorpusManifestIsTraceable(t *testing.T) {
	data, err := os.ReadFile("testdata/clienthello-corpus/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SchemaVersion string `json:"schema_version"`
		Entries       []struct {
			ID        string   `json:"id"`
			Kind      string   `json:"kind"`
			Source    string   `json:"source"`
			License   string   `json:"license"`
			CoveredBy []string `json:"covered_by"`
		} `json:"entries"`
		AcceptanceGaps []string `json:"acceptance_gaps"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "ja3proxy-clienthello-corpus/1" || len(manifest.Entries) < 5 || len(manifest.AcceptanceGaps) == 0 {
		t.Fatalf("incomplete corpus manifest: %+v", manifest)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entry.ID == "" || entry.Kind == "" || entry.Source == "" || entry.License == "" || len(entry.CoveredBy) == 0 {
			t.Fatalf("corpus entry lacks provenance: %+v", entry)
		}
		if seen[entry.ID] {
			t.Fatalf("duplicate corpus ID %q", entry.ID)
		}
		seen[entry.ID] = true
	}
}

func TestOpenSSLCorpusGolden(t *testing.T) {
	encoded, err := os.ReadFile("testdata/clienthello-corpus/openssl-3.5.5-tls13.hex")
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	stream := NewStream(DefaultLimits())
	stream.Feed(recordBytes)
	capture := stream.Finish("closed")
	if capture.Status != "complete" {
		t.Fatalf("OpenSSL capture status = %s (%s)", capture.Status, capture.ErrorCode)
	}
	hello, err := Parse(capture.Raw)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := Calculate(hello, capture.Raw, capture.Records)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "openssl.test" ||
		fingerprints.JA3Hash != "7c5d0596cedb9c086e8bebef099e73dc" ||
		fingerprints.JA4 != "t13d031100_55b375c5d22e_199193a2bd39" ||
		fingerprints.NormalizedSHA256 != "95d6362dbb1528cc15537663a9d82b8f463cb36c1cb6361594779fe694ccc8d1" {
		t.Fatalf("unexpected OpenSSL vector: hello=%+v fingerprints=%+v", hello, fingerprints)
	}
}
