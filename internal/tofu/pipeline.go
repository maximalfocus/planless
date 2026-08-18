// Package tofu drives the real infrastructure-as-code toolchain and records
// what each stage actually produced.
//
// Four artifacts matter, and the transcript keeps them apart on purpose: the
// source configuration, the resolved desired state, the artifact a policy would
// evaluate, and the state that was applied. Each carries its own digest.
package tofu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/fixtures"
)

// Scenario is one enumerated pipeline run. Nothing else can be started: there
// is no free-form configuration, variable file, resource or address input.
type Scenario struct {
	ID      string
	VarFile string

	// SkipApply stops after producing the plan artifact. SkipRemote makes the
	// run touch no service at all, which is how initialization is proved to
	// need no network.
	SkipApply  bool
	SkipRemote bool
}

// Scenarios is the complete set of runs this pipeline offers.
var Scenarios = map[string]Scenario{
	"secure-apply": {ID: "secure-apply", VarFile: "secure.tfvars"},
	"offline-init": {ID: "offline-init", VarFile: "secure.tfvars", SkipApply: true, SkipRemote: true},
}

// Config is resolved from the container image layout, not from user input.
type Config struct {
	Tofu      string
	InfraDir  string
	WorkDir   string
	DataDir   string
	TempDir   string
	CLIConfig string
	StateAPI  string
}

// Transcript is the deterministic record of one pipeline run.
type Transcript struct {
	Scenario string  `json:"scenario"`
	Stages   []Stage `json:"stages"`

	// SourceDigest identifies the configuration as written.
	SourceDigest string `json:"source_configuration_digest"`

	// PlanArtifact identifies the binary plan file this run produced. The
	// toolchain's plan format carries run-specific data, so this digest is a
	// per-run identity rather than a property of the desired state — which is
	// exactly what a binding between an approved artifact and an applied
	// artifact needs it to be.
	PlanArtifact string `json:"plan_artifact_digest"`

	// EvaluatedDigest identifies the resolved desired state: the artifact a
	// policy would read. The same configuration and values always produce the
	// same digest here.
	EvaluatedDigest string `json:"resolved_desired_state_digest"`

	// AppliedDigest identifies the platform state that resulted.
	AppliedDigest string `json:"applied_state_digest"`

	// EvaluatedBy names what read the resolved desired state. In this slice
	// nothing does, and saying so is the honest answer.
	EvaluatedBy string `json:"artifact_evaluated_by"`

	// SourceLayout records what the source text does and does not contain. It
	// is the honest half of the resolved-artifact claim.
	SourceLayout []Finding `json:"source_layout_findings"`

	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

// Stage records one toolchain invocation.
type Stage struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output,omitempty"`
}

// Plan produces the canonical resolved artifact for one scenario and returns
// it, without applying anything.
func Plan(cfg Config, scenario Scenario) ([]byte, error) {
	t := &Transcript{Scenario: scenario.ID}
	if err := prepare(cfg); err != nil {
		return nil, err
	}
	if err := t.run(cfg, "init", "-input=false", "-no-color"); err != nil {
		return nil, err
	}
	if err := t.run(cfg, "plan", "-input=false", "-no-color", "-lock=false",
		"-var-file="+scenario.VarFile, "-out=plan.tfplan"); err != nil {
		return nil, err
	}
	planJSON, err := t.capture(cfg, "show", "-json", "plan.tfplan")
	if err != nil {
		return nil, err
	}
	return CanonicalPlan(planJSON)
}

// Run executes one enumerated scenario end to end.
func Run(cfg Config, scenario Scenario) (*Transcript, error) {
	t := &Transcript{Scenario: scenario.ID, EvaluatedBy: "nothing: no policy gate exists in this configuration"}

	if err := prepare(cfg); err != nil {
		return t, err
	}
	sourceDigest, err := digestTree(cfg.WorkDir)
	if err != nil {
		return t, err
	}
	t.SourceDigest = sourceDigest

	if err := t.run(cfg, "init", "-input=false", "-no-color"); err != nil {
		return t, err
	}
	planPath := filepath.Join(cfg.WorkDir, "plan.tfplan")
	if err := t.run(cfg, "plan", "-input=false", "-no-color", "-lock=false",
		"-var-file="+scenario.VarFile, "-out=plan.tfplan"); err != nil {
		return t, err
	}
	planBytes, err := os.ReadFile(planPath)
	if err != nil {
		return t, err
	}
	t.PlanArtifact = canon.Digest(planBytes)

	planJSON, err := t.capture(cfg, "show", "-json", "plan.tfplan")
	if err != nil {
		return t, err
	}
	resolved, err := CanonicalPlan(planJSON)
	if err != nil {
		return t, err
	}
	t.EvaluatedDigest = canon.Digest(resolved)
	if err := os.WriteFile(filepath.Join(cfg.WorkDir, "plan.json"), resolved, 0o600); err != nil {
		return t, err
	}

	findings, err := CheckSources(cfg.WorkDir)
	if err != nil {
		return t, err
	}
	t.SourceLayout = findings
	if len(findings) > 0 {
		return t, fmt.Errorf("configuration source layout is wrong: %+v", findings)
	}
	if missing := ValuesMissingFromPlan(resolved); len(missing) > 0 {
		return t, fmt.Errorf("resolved artifact is missing security-relevant values %v", missing)
	}

	if !scenario.SkipApply {
		if err := t.run(cfg, "apply", "-input=false", "-no-color", "-lock=false", "plan.tfplan"); err != nil {
			return t, err
		}
	}
	if !scenario.SkipRemote {
		applied, err := appliedDigest(cfg.StateAPI)
		if err != nil {
			return t, err
		}
		t.AppliedDigest = applied
	}
	t.Passed = true
	return t, nil
}

// prepare materializes the working tree: the checked-in configuration plus the
// fixture object bytes, which come from the same embedded fixtures the tests
// pin, so the applied content cannot drift from the checked-in content.
func prepare(cfg Config) error {
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(cfg.WorkDir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("work directory %s is not empty; every run starts from fresh state", cfg.WorkDir)
	}
	src, err := os.OpenRoot(cfg.InfraDir)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.CopyFS(cfg.WorkDir, src.FS()); err != nil {
		return err
	}
	dataDir := filepath.Join(cfg.WorkDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	for name, body := range map[string][]byte{
		fixtures.ObjectRefunds: fixtures.RefundsCSV(),
		fixtures.ObjectStatus:  fixtures.StatusJSON(),
	} {
		if err := os.WriteFile(filepath.Join(dataDir, name), body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transcript) run(cfg Config, args ...string) error {
	out, err := t.exec(cfg, args...)
	if err != nil {
		t.Error = fmt.Sprintf("%s: %v", args[0], err)
		t.Stages = append(t.Stages, Stage{Name: args[0], Command: command(cfg, args), ExitCode: exitCode(err), Output: string(out)})
		return err
	}
	t.Stages = append(t.Stages, Stage{Name: args[0], Command: command(cfg, args), Output: summarize(out)})
	return nil
}

func (t *Transcript) capture(cfg Config, args ...string) ([]byte, error) {
	out, err := t.exec(cfg, args...)
	if err != nil {
		t.Error = fmt.Sprintf("%s: %v", args[0], err)
		t.Stages = append(t.Stages, Stage{Name: args[0], Command: command(cfg, args), ExitCode: exitCode(err), Output: string(out)})
		return nil, err
	}
	t.Stages = append(t.Stages, Stage{Name: args[0], Command: command(cfg, args)})
	return out, nil
}

func (t *Transcript) exec(cfg Config, args ...string) ([]byte, error) {
	cmd := exec.Command(cfg.Tofu, args...)
	cmd.Dir = cfg.WorkDir
	cmd.Env = []string{
		"HOME=" + cfg.WorkDir,
		"TF_CLI_CONFIG_FILE=" + cfg.CLIConfig,
		"TF_DATA_DIR=" + cfg.DataDir,
		"TF_IN_AUTOMATION=1",
		"TF_INPUT=0",
		"CHECKPOINT_DISABLE=1",
		// The plugin protocol needs a directory for its local socket.
		"TMPDIR=" + cfg.TempDir,
		"PATH=/usr/local/bin",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return append(stdout.Bytes(), stderr.Bytes()...), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// summarize keeps a successful stage's transcript entry to the line that says
// what it did. Full output is kept only when a stage fails, where it is the
// evidence.
func summarize(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}

func command(cfg Config, args []string) string {
	return filepath.Base(cfg.Tofu) + " " + join(args)
}

func join(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode()
	}
	return 1
}

// CanonicalPlan renders the toolchain's machine-readable plan as a stable
// artifact.
//
// The toolchain stamps each plan with the moment it was produced. That field
// says nothing about the desired state, and keeping it would mean the same
// configuration produced a different artifact every run, so it is removed
// before the artifact is digested. Nothing else is altered.
func CanonicalPlan(raw []byte) ([]byte, error) {
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("plan artifact is not valid JSON: %w", err)
	}
	delete(tree, "timestamp")
	return canon.Marshal(tree)
}

func digestTree(dir string) (string, error) {
	files := map[string]any{}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = canon.Digest(body)
		return nil
	})
	if err != nil {
		return "", err
	}
	return canon.DigestOf(files)
}

func appliedDigest(stateAPI string) (string, error) {
	client := &httpClient{timeout: 10 * time.Second}
	return client.stateDigest(stateAPI)
}
