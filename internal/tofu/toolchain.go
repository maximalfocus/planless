package tofu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/fixtures"
)

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

// Plan produces the canonical resolved artifact for one scenario without
// applying anything. It exists so the checked-in policy fixtures can be
// regenerated from a real plan rather than written by hand.
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
	return filepath.Base(cfg.Tofu) + " " + strings.Join(args, " ")
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
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
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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
