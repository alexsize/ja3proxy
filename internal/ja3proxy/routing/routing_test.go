package routing

import (
	"net/netip"
	"testing"
)

func TestStoreResolvesTwoPhaseRulesByPriorityAndSpecificity(t *testing.T) {
	store := &Store{}
	config := Config{
		Default: Action{Mode: "allow_and_record"},
		Rules: []Rule{
			{ID: "wildcard", Priority: 20, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "*.example.com"}, Action: Action{Mode: "PASSTHROUGH"}},
			{ID: "exact", Priority: 20, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "api.example.com"}, Action: Action{Mode: "MITM_REISSUE"}},
			{ID: "low-priority", Priority: 10, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "api.example.com"}, Action: Action{Mode: "BLOCK"}},
			{ID: "post-sni", Priority: 1, Enabled: true, Phase: PhasePostClientHello, Match: Match{Host: "secure.example.com"}, Action: Action{Mode: "MITM_REISSUE"}},
		},
	}
	if err := store.SetValidated(config); err != nil {
		t.Fatal(err)
	}

	pre := store.Resolve(PhasePreTLS, Request{Host: "api.example.com", Port: 443})
	if pre.ConfigVersion != 1 || pre.MatchedRuleID != "low-priority" || pre.MatchedRulePriority != 10 || pre.Action.Mode != "BLOCK" {
		t.Fatalf("pre-TLS decision = %+v", pre)
	}
	if len(pre.CandidateRuleIDs) != 3 || pre.CandidateRuleIDs[0] != "low-priority" {
		t.Fatalf("pre-TLS candidates = %v", pre.CandidateRuleIDs)
	}

	post := store.Resolve(PhasePostClientHello, Request{Host: "connect.example.com", SNI: "secure.example.com", Port: 443})
	if post.MatchedRuleID != "post-sni" || post.MatchReason != "host_exact" {
		t.Fatalf("post-ClientHello decision = %+v", post)
	}
}

func TestStoreMatchesCIDRPortDeviceTagAndUsername(t *testing.T) {
	store := &Store{}
	if err := store.SetValidated(Config{Rules: []Rule{{
		ID: "mobile", Priority: 1, Enabled: true, Phase: PhasePreTLS,
		Match:  Match{CIDR: "192.0.2.0/24", Port: 443, DeviceTag: "mobile", Username: "iphone017"},
		Action: Action{Mode: "MITM_REISSUE", TLSProfile: "mobile-profile"},
	}}}); err != nil {
		t.Fatal(err)
	}
	decision := store.Resolve(PhasePreTLS, Request{
		IP: netip.MustParseAddr("192.0.2.10"), Port: 443, DeviceTags: []string{"mobile", "ios"}, Username: "iphone017",
	})
	if decision.MatchedRuleID != "mobile" || decision.MatchReason != "cidr+port+device_tag+username" || decision.Action.TLSProfile != "mobile-profile" {
		t.Fatalf("metadata decision = %+v", decision)
	}
	if got := store.Resolve(PhasePreTLS, Request{IP: netip.MustParseAddr("198.51.100.10"), Port: 443, DeviceTags: []string{"mobile"}, Username: "iphone017"}); got.MatchedRuleID != "" || got.MatchReason != "default" {
		t.Fatalf("non-matching decision = %+v", got)
	}
}

func TestValidateRejectsAmbiguousRulesAndAcceptsDisjointRules(t *testing.T) {
	ambiguous := Config{Rules: []Rule{
		{ID: "one", Priority: 1, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "*.example.com"}},
		{ID: "two", Priority: 1, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "*.example.com"}},
	}}
	if err := Validate(ambiguous); err == nil {
		t.Fatal("Validate() accepted ambiguous rules")
	}
	disjoint := Config{Rules: []Rule{
		{ID: "one", Priority: 1, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "one.example.com"}},
		{ID: "two", Priority: 1, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "two.example.com"}},
	}}
	if err := Validate(disjoint); err != nil {
		t.Fatalf("Validate() rejected disjoint rules: %v", err)
	}
}

func TestValidateRejectsUnsupportedActionMode(t *testing.T) {
	err := Validate(Config{Rules: []Rule{{
		ID: "bad-action", Priority: 1, Enabled: true, Phase: PhasePreTLS,
		Match: Match{Host: "example.com"}, Action: Action{Mode: "REWRITE"},
	}}})
	if err == nil {
		t.Fatal("Validate() accepted unsupported action mode")
	}
}

func TestStoreSnapshotIsImmutableAndVersioned(t *testing.T) {
	store := &Store{}
	config := Config{Rules: []Rule{{ID: "one", Priority: 1, Enabled: true, Phase: PhasePreTLS, Match: Match{Host: "one.example.com"}}}}
	if err := store.SetValidated(config); err != nil {
		t.Fatal(err)
	}
	config.Rules[0].ID = "changed-outside-store"
	snapshot, version, ok := store.Snapshot()
	if !ok || version != 1 || snapshot.Rules[0].ID != "one" {
		t.Fatalf("snapshot = %+v, version=%d, ok=%v", snapshot, version, ok)
	}
	snapshot.Rules[0].ID = "changed-snapshot"
	if got := store.Resolve(PhasePreTLS, Request{Host: "one.example.com"}); got.MatchedRuleID != "one" {
		t.Fatalf("store changed through snapshot = %+v", got)
	}
}
