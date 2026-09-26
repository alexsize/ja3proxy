package appversion

import "testing"

func TestFromUserAgentReturnsOnlyUnverifiedStructuredClaims(t *testing.T) {
	evidence := FromUserAgent("Mozilla/5.0 (iPhone) ExampleApp/4.2.1 okhttp/4.12.0")
	if len(evidence) != 2 {
		t.Fatalf("evidence = %+v, want app and HTTP library claims", evidence)
	}
	if evidence[0].Product != "ExampleApp" || evidence[0].Version != "4.2.1" || evidence[0].Source != SourceUserAgent || evidence[0].Confidence != ConfidenceLow || evidence[0].Status != StatusUnverified {
		t.Fatalf("application claim = %+v", evidence[0])
	}
	if evidence[1].Product != "okhttp" || evidence[1].Version != "4.12.0" {
		t.Fatalf("library claim = %+v", evidence[1])
	}
}

func TestFromUserAgentIgnoresGenericTokensAndBoundsResults(t *testing.T) {
	if got := FromUserAgent("Mozilla/5.0 AppleWebKit/605.1.15 Safari/17.0"); len(got) != 0 {
		t.Fatalf("generic browser tokens = %+v", got)
	}
	if got := FromUserAgent("Example/1.0, Example/1.0 Broken/name"); len(got) != 1 || got[0].Version != "1.0" {
		t.Fatalf("deduplicated claims = %+v", got)
	}
	var many string
	for index := 0; index < MaxCandidates+4; index++ {
		many += " Product" + string(rune('A'+index)) + "/1"
	}
	if got := FromUserAgent(many); len(got) != MaxCandidates {
		t.Fatalf("candidate count = %d, want bounded to %d", len(got), MaxCandidates)
	}
}

func TestAppendUserAgentDeduplicatesAndBoundsAcrossRequests(t *testing.T) {
	claims := AppendUserAgent(nil, "Example/1.0")
	claims = AppendUserAgent(claims, "example/1.0")
	if len(claims) != 1 {
		t.Fatalf("repeated claim count = %d", len(claims))
	}
	for index := 0; index < MaxCandidates+3; index++ {
		claims = AppendUserAgent(claims, "Product"+string(rune('A'+index))+"/1")
	}
	if len(claims) != MaxCandidates {
		t.Fatalf("aggregate claim count = %d, want %d", len(claims), MaxCandidates)
	}
}

func TestFromUserAgentRejectsOversizedHeaderValue(t *testing.T) {
	if got := FromUserAgent("Example/1.0 " + string(make([]byte, maxUserAgentBytes))); len(got) != 0 {
		t.Fatalf("oversized value produced claims: %+v", got)
	}
}
