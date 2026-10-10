package plugin

import (
	"reflect"
	"strings"
	"testing"

	"cpa-key-billing/internal/billing"
)

func TestSchedulerCandidateFilterDelegatesPriorityAndWeightsToHost(t *testing.T) {
	app, scope := configuredRoutingApp(t, billing.RouteRule{CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}})
	candidates := []SchedulerAuthCandidate{
		priorityCandidate("outside", "codex", "20", "1"),
		priorityCandidate("zed-high", "zed", "3", "2"),
		priorityCandidate("zed-low", "zed", "0", "1"),
		priorityCandidate("zed-zero", "zed", "4", "0"),
	}
	for i := 0; i < 4; i++ {
		req := schedulerRequest(scope, candidates...)
		req.SupportsCandidateFiltering = true
		before := string(mustMarshal(t, req))
		raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, req))
		if err != nil {
			t.Fatal(err)
		}
		var got SchedulerPickResponse
		decodeResult(t, raw, &got)
		if !got.Handled || got.AuthID != "" || !reflect.DeepEqual(got.AllowedAuthIDs, []string{"zed-high", "zed-low", "zed-zero"}) {
			t.Fatalf("response=%+v", got)
		}
		if string(mustMarshal(t, req)) != before {
			t.Fatal("candidate metadata mutated")
		}
	}
	if len(app.scheduler.keys) != 0 {
		t.Fatal("host filtering advanced plugin round-robin state")
	}
}

func TestSchedulerCandidateFilterPreservesDenyRules(t *testing.T) {
	app, scope := configuredRoutingApp(t, billing.RouteRule{
		CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}},
		DeniedCredentialIDs: []string{billing.CredentialFingerprint("zed-denied")},
	})
	req := schedulerRequest(scope, priorityCandidate("zed-allowed", "zed", "0", "1"), priorityCandidate("zed-denied", "zed", "10", "1"), priorityCandidate("outside", "codex", "20", "1"))
	req.SupportsCandidateFiltering = true
	raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, req))
	if err != nil {
		t.Fatal(err)
	}
	var got SchedulerPickResponse
	decodeResult(t, raw, &got)
	if !got.Handled || got.AuthID != "" || !reflect.DeepEqual(got.AllowedAuthIDs, []string{"zed-allowed"}) {
		t.Fatalf("response=%+v", got)
	}
}

func TestSchedulerCandidateFilterUnchangedPoolDelegates(t *testing.T) {
	for _, rule := range []billing.RouteRule{{}, {CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}}} {
		app, scope := configuredRoutingApp(t, rule)
		req := schedulerRequest(scope, priorityCandidate("zed", "zed", "0", "1"))
		req.SupportsCandidateFiltering = true
		raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, req))
		if err != nil {
			t.Fatal(err)
		}
		var got SchedulerPickResponse
		decodeResult(t, raw, &got)
		if got.Handled || got.AllowedAuthIDs != nil || got.AuthID != "" {
			t.Fatalf("unchanged pool=%+v", got)
		}
	}
}

func TestSchedulerCandidateFilterNoAuthorizedCandidateFailsClosed(t *testing.T) {
	app, scope := configuredRoutingApp(t, billing.RouteRule{CredentialProviders: []billing.CredentialProviderSelector{{Source: billing.CredentialSourceAuthFiles, Provider: "zed"}}})
	req := schedulerRequest(scope, priorityCandidate("outside", "codex", "10", "1"))
	req.SupportsCandidateFiltering = true
	raw, err := app.HandleMethod(MethodSchedulerPick, mustMarshal(t, req))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"no_routed_credential"`) {
		t.Fatalf("response=%s", raw)
	}
}
