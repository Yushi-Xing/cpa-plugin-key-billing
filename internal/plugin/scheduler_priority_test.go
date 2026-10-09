package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"cpa-key-billing/internal/billing"
)

func priorityCandidate(id, provider, priority, weight string) SchedulerAuthCandidate {
	return SchedulerAuthCandidate{ID: id, Provider: provider, Attributes: map[string]string{"path": "/fictional/" + id + ".json", "priority": priority, "weight": weight}}
}

func TestSchedulerCredentialPolicyPrecedesPriority(t *testing.T) {
	zedOnly := billing.RouteRule{CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}}
	for _, tc := range []struct {
		name       string
		rule       billing.RouteRule
		candidates []SchedulerAuthCandidate
		want       string
	}{
		{"lower-priority Zed", zedOnly, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed", "zed", "0", "1")}, "zed"},
		{"negative-priority Zed", zedOnly, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "0", "1"), priorityCandidate("zed", "zed", "-5", "1")}, "zed"},
		{"explicit credential", billing.RouteRule{CredentialIDs: []string{billing.CredentialFingerprint("zed")}}, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed", "zed", "0", "1")}, "zed"},
		{"deny Codex", billing.RouteRule{DeniedCredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "codex"}}}, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed", "zed", "0", "1")}, "zed"},
		{"highest authorized tier", zedOnly, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed-high", "zed", "3", "1"), priorityCandidate("zed-low", "zed", "0", "1000")}, "zed-high"},
		{"zero-weight high tier", zedOnly, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed-zero", "zed", "3", "0"), priorityCandidate("zed", "zed", "0", "1")}, "zed"},
		{"invalid-weight high tier", zedOnly, []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed-invalid", "zed", "3", "invalid"), priorityCandidate("zed", "zed", "0", "1")}, "zed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, scope := configuredRoutingApp(t, tc.rule)
			req := schedulerRequest(scope, tc.candidates...)
			before := string(mustMarshal(t, req))
			raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, req))
			if err != nil {
				t.Fatal(err)
			}
			var result SchedulerPickResponse
			decodeResult(t, raw, &result)
			if !result.Handled || result.AuthID != tc.want {
				t.Fatalf("result=%+v, want %s", result, tc.want)
			}
			if string(mustMarshal(t, req)) != before {
				t.Fatal("candidate metadata mutated")
			}
		})
	}
}

func TestSchedulerUnchangedPolicyDelegatesAcrossPriorities(t *testing.T) {
	for _, rule := range []billing.RouteRule{{}, {CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "codex"}, {Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}}} {
		app, scope := configuredRoutingApp(t, rule)
		raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, schedulerRequest(scope, priorityCandidate("codex", "codex", "10", "1"), priorityCandidate("zed", "zed", "0", "1"))))
		if err != nil {
			t.Fatal(err)
		}
		var result SchedulerPickResponse
		decodeResult(t, raw, &result)
		if result.Handled || result.AuthID != "" {
			t.Fatalf("unchanged policy should delegate: %+v", result)
		}
	}
}

func TestSchedulerPriorityWithinAuthorizedTierKeepsWeights(t *testing.T) {
	app, scope := configuredRoutingApp(t, billing.RouteRule{CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}})
	candidates := []SchedulerAuthCandidate{priorityCandidate("codex", "codex", "20", "1000"), priorityCandidate("zed-a", "zed", "3", "2"), priorityCandidate("zed-b", "zed", "3", "1"), priorityCandidate("zed-low", "zed", "0", "1000")}
	counts := map[string]int{}
	for i := 0; i < 12; i++ {
		raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, schedulerRequest(scope, candidates...)))
		if err != nil {
			t.Fatal(err)
		}
		var result SchedulerPickResponse
		decodeResult(t, raw, &result)
		if !result.Handled {
			t.Fatal("restricted subset delegated")
		}
		counts[result.AuthID]++
	}
	if counts["zed-a"] != 8 || counts["zed-b"] != 4 || len(counts) != 2 {
		t.Fatalf("unexpected tier/weight distribution: %v", counts)
	}
}

func TestSchedulerRoutedPriorityParsingMatchesHost(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{"", 0}, {" 3 ", 3}, {"-5", -5}, {"invalid", 0}, {strings.Repeat("9", 100), 0}} {
		if got := candidatePriority(priorityCandidate("fixture", "zed", tc.raw, "1")); got != tc.want {
			t.Fatalf("priority %q=%d, want %d", tc.raw, got, tc.want)
		}
	}
	input := []SchedulerAuthCandidate{priorityCandidate("negative", "zed", "-5", "1"), priorityCandidate("invalid", "zed", "invalid", "1"), priorityCandidate("default", "zed", "", "1")}
	before, _ := json.Marshal(input)
	got := highestPriorityRoutedCandidates(input)
	if len(got) != 2 || got[0].ID != "invalid" || got[1].ID != "default" {
		t.Fatalf("unexpected zero-priority tier: %+v", got)
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
}
