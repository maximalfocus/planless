// Command contain asserts the demonstration's containment rules over the
// resolved Compose configuration supplied on standard input.
//
// It reads no host path, needs no container runtime socket, and mutates
// nothing. A violated rule exits non-zero.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/maximalfocus/planless/internal/containment"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "contain: reading configuration:", err)
		os.Exit(2)
	}
	findings, err := containment.Check(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contain:", err)
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"check":    "compose-containment",
		"findings": findings,
		"passed":   len(findings) == 0,
	}, "", "  ")
	fmt.Println(string(out))
	if len(findings) > 0 {
		os.Exit(1)
	}
}
