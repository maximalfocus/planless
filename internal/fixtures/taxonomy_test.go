package fixtures

import (
	"os"
	"strings"
	"testing"
)

// The claim is exactly these three, and the refusals are exactly these six. A
// change to either is a deliberate edit here, not a drift.
func TestTaxonomyBoundaryIsExact(t *testing.T) {
	claimed := Claimed()
	want := []string{"A05:2021", "CWE-732", "CWE-1327"}
	if len(claimed) != len(want) {
		t.Fatalf("claimed %v, want %v", claimed, want)
	}
	for i := range want {
		if claimed[i] != want[i] {
			t.Fatalf("claimed %v, want %v", claimed, want)
		}
	}

	refused := map[string]bool{}
	for _, id := range NotClaimed() {
		refused[id] = true
	}
	for _, id := range []string{"CWE-1032", "CWE-16", "CWE-668", "CWE-276", "A06:2021", "API8:2023"} {
		if !refused[id] {
			t.Fatalf("%s is no longer explicitly refused", id)
		}
	}
	if len(refused) != 6 {
		t.Fatalf("refused %v", NotClaimed())
	}
}

// Every entry says why. A taxonomy claim without a reason is a number somebody
// liked the look of.
func TestEveryTaxonomyEntryCarriesItsReason(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Taxonomy {
		if c.ID == "" || c.Title == "" || len(c.Rationale) < 40 {
			t.Fatalf("incomplete taxonomy entry: %+v", c)
		}
		if seen[c.ID] {
			t.Fatalf("duplicate taxonomy entry %s", c.ID)
		}
		seen[c.ID] = true
	}
}

// The two refusals that are easiest to get wrong, because both are Categories
// whose mapping usage is Prohibited and both look like they would fit.
func TestProhibitedCategoriesAreRefusedForTheRightReason(t *testing.T) {
	for _, id := range []string{"CWE-1032", "CWE-16"} {
		for _, c := range Taxonomy {
			if c.ID != id {
				continue
			}
			if c.Claimed {
				t.Fatalf("%s is claimed", id)
			}
			if !strings.Contains(strings.ToLower(c.Rationale), "prohibited") {
				t.Fatalf("%s is refused without naming its mapping usage: %s", id, c.Rationale)
			}
		}
	}
}

// The documentation must carry the same boundary the fixture does.
func TestDocumentationCarriesTheTaxonomyBoundary(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(body)
	for _, c := range Taxonomy {
		if !strings.Contains(readme, c.ID) {
			t.Fatalf("the documentation does not mention %s", c.ID)
		}
	}
}
