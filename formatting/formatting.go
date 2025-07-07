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
	ResultStatusFailed ResultStatus = "FAILED"
	ResultStatusPassed ResultStatus = "PASSED"
)

// RunGofmt walks the given path, calls `gofmt -l` on each .go file,
// and reports any files that are not yet formatted.
func RunGofmt(path string) FormattingResult {
	filesNeedingFormat := runGofmt(path)

	status := ResultStatusPassed
	if len(filesNeedingFormat) > 0 {
		status = ResultStatusFailed
	}

	return FormattingResult{
		Status:       status,
		Tool:         "gofmt",
		FilesChanged: filesNeedingFormat,
	}
}

func runGofmt(path string) []string {
	var notFormatted []string

	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}

		// `-l` prints the file name if it would change.
		out := run("gofmt", "-l", p)
		if strings.TrimSpace(out) != "" {
			notFormatted = append(notFormatted, filepath.Base(p))
		}
		return nil
	})

	return notFormatted
}

func run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
