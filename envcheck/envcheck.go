package envcheck

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type EnvIssue struct {
	File     string `json:"file"`
	Variable string `json:"variable"`
	Problem  string `json:"problem"`
}

type EnvVariablesResult struct {
	Status ResultStatus `json:"status"`
	Issues []EnvIssue   `json:"issues"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

// ScanEnvFiles scans for environment files in the given path and returns environment check results
func ScanEnvFiles(path string) EnvVariablesResult {
	issues := scanEnvFile(path)

	status := ResultStatusPassed
	if len(issues) > 0 {
		status = ResultStatusWarning
	}

	return EnvVariablesResult{
		Status: status,
		Issues: issues,
	}
}

func scanEnvFile(path string) []EnvIssue {
	var issues []EnvIssue
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if filepath.Base(p) == ".env" {
			data, _ := ioutil.ReadFile(p)
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				if strings.Contains(l, "SECRET") {
					parts := strings.SplitN(l, "=", 2)
					if len(parts) == 2 {
						issues = append(issues, EnvIssue{
							File:     ".env",
							Variable: strings.TrimSpace(parts[0]),
							Problem:  "Hardcoded secret",
						})
					}
				}
			}
		}
		return nil
	})
	return issues
}
