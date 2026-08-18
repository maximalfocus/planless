package selfcheck

import "testing"

// The assertions run wherever the tests run; what is pinned here is the set of
// properties the demonstration claims, so a silently dropped assertion is a
// test failure rather than a quieter report.
func TestEveryClaimedPropertyIsAsserted(t *testing.T) {
	results := Run([]string{t.TempDir()})
	want := []string{
		"non_root_user",
		"capabilities_dropped",
		"no_new_privileges",
		"read_only_root_filesystem",
		"no_default_route",
		"external_names_do_not_resolve",
		"external_addresses_do_not_connect",
	}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Name] = true
		if r.Observed == "" {
			t.Fatalf("assertion %s recorded nothing it observed", r.Name)
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("assertion %s is missing", w)
		}
	}
	if len(results) != len(want)+1 {
		t.Fatalf("expected one tmpfs assertion beside the fixed set, got %d results", len(results))
	}
}

func TestFailedFiltersResults(t *testing.T) {
	results := []Result{{Name: "a", Passed: true}, {Name: "b"}, {Name: "c"}}
	failed := Failed(results)
	if len(failed) != 2 || failed[0].Name != "b" || failed[1].Name != "c" {
		t.Fatalf("unexpected failures: %+v", failed)
	}
}
