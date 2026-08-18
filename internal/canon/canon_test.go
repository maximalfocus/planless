package canon

import (
	"strings"
	"testing"
)

func TestMarshalIsCanonical(t *testing.T) {
	a := map[string]any{"b": 1, "a": []any{"x", "y"}, "c": map[string]any{"z": true, "y": nil}}
	b := map[string]any{"c": map[string]any{"y": nil, "z": true}, "a": []any{"x", "y"}, "b": 1}
	ab, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(bb) {
		t.Fatalf("key order changed the encoding:\n%s\n%s", ab, bb)
	}
	want := `{"a":["x","y"],"b":1,"c":{"y":null,"z":true}}`
	if string(ab) != want {
		t.Fatalf("got %s want %s", ab, want)
	}
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	b, err := Marshal(map[string]any{"note": "a<b>c&d"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "a<b>c&d") {
		t.Fatalf("unexpected escaping: %s", b)
	}
}

func TestDigestStability(t *testing.T) {
	d1, err := DigestOf(map[string]any{"x": 1, "y": "two"})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DigestOf(map[string]any{"y": "two", "x": 1})
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest is order dependent: %s vs %s", d1, d2)
	}
	if !strings.HasPrefix(d1, "sha256:") || len(d1) != len("sha256:")+64 {
		t.Fatalf("unexpected digest shape: %s", d1)
	}
	if d3, _ := DigestOf(map[string]any{"x": 2, "y": "two"}); d3 == d1 {
		t.Fatal("different content produced the same digest")
	}
}

func TestDigestOfBytes(t *testing.T) {
	if got, want := Digest([]byte("")), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
