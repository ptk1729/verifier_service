package linting

import (
	"os/exec"
	"path/filepath"
	"strings"
)

type LintingResult struct {
	Status   ResultStatus `json:"status"`
	Errors   []string     `json:"errors"`
	Warnings []string     `json:"warnings"`
	Tool     string       `json:"tool"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

// RunLint checks code in the given folder with go vet (errors)
// and golint (warnings) without changing any file.
func RunLint(path string) LintingResult {
	// first run go mod tidy and other commands to make sure the code is up to date
	runCmd(path, "go", "mod", "tidy")
	errs := runGovet(path)
	warns := runGolint(path)

	status := ResultStatusPassed
	if len(errs) > 0 {
		status = ResultStatusFailed
	} else if len(warns) > 0 {
		status = ResultStatusWarning
	}

	return LintingResult{
		Status:   status,
		Errors:   errs,
		Warnings: warns,
		Tool:     "golangci-lint",
	}
}

// ----------------------- helpers -----------------------

func runGovet(dir string) []string {
	out, _ := runCmd(dir, "go", "vet", "./...")
	return split(out)
}

func runGolint(dir string) []string {
	out, _ := runCmd(dir, "golangci-lint", "run", "./...")
	return split(out)
}

func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir // run inside the target folder
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 { // command failed but printed nothing
		return err.Error(), err
	}
	return string(out), err
}

func split(s string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			// keep only the base file name for shorter output
			if idx := strings.Index(l, ":"); idx > 0 {
				l = filepath.Base(l[:idx]) + l[idx:]
			}
			lines = append(lines, l)
		}
	}
	return lines
}
