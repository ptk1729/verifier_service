package formatting

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FormattingResult struct {
	Status       ResultStatus `json:"status"`
	Tool         string       `json:"tool"`
	FilesChanged []string     `json:"files_changed"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

// RunGofmt runs gofmt on all Go files in the given path and returns formatting results
func RunGofmt(path string) FormattingResult {
	filesChanged := runGofmt(path)

	status := ResultStatusPassed
	if len(filesChanged) > 0 {
		status = ResultStatusPassed
	} else {
		status = ResultStatusPassed // Gofmt may not change anything
	}

	return FormattingResult{
		Status:       status,
		Tool:         "gofmt",
		FilesChanged: filesChanged,
	}
}

func runGofmt(path string) []string {
	changed := []string{}
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if strings.HasSuffix(p, ".go") {
			out := run("gofmt", "-l", "-w", p)
			if strings.TrimSpace(out) != "" {
				changed = append(changed, filepath.Base(p))
			}
		}
		return nil
	})
	return changed
}

func run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
