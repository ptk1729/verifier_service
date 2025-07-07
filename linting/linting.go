package linting

import (
	"os"
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

// RunGolint runs golint on all Go files in the given path and returns linting results
func RunGolint(path string) LintingResult {
	warnings, errors := runGolint(path)

	status := ResultStatusPassed
	if len(errors) > 0 {
		status = ResultStatusFailed
	} else if len(warnings) > 0 {
		status = ResultStatusWarning
	}

	return LintingResult{
		Status:   status,
		Errors:   errors,
		Warnings: warnings,
		Tool:     "golint",
	}
}

func runGolint(path string) (warnings, errors []string) {
	files := []string{}
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if strings.HasSuffix(p, ".go") {
			files = append(files, p)
		}
		return nil
	})

	for _, f := range files {
		out := run("golint", f)
		if strings.Contains(out, "warning") {
			warnings = append(warnings, strings.TrimSpace(out))
		} else if out != "" {
			warnings = append(warnings, strings.TrimSpace(out))
		}
	}
	return
}

func run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
