package gotest

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ptk1729/verifier_service/types"
)

// RunCoverage executes `go test` with coverage across all packages and returns coverage percent.
func RunCoverage(repoPath string) types.TestCoverageResult {
	coverProfile := filepath.Join(".", "coverage.out")

	testCmd := exec.Command("go", "test", "./...", "-coverprofile", coverProfile, "-covermode", "atomic")
	testCmd.Dir = repoPath
	var testOut bytes.Buffer
	testCmd.Stdout = &testOut
	testCmd.Stderr = &testOut

	err := testCmd.Run()
	testOutput := strings.TrimSpace(testOut.String())

	hasFailures := strings.Contains(testOutput, "FAIL")

	if hasFailures {
		return types.TestCoverageResult{
			Status:          types.ResultStatusFailed,
			CoveragePercent: 0,
			Tool:            "go test",
			ErrorMessage:    "errors in go test",
		}
	}

	if err != nil {
		return types.TestCoverageResult{
			Status:          types.ResultStatusFailed,
			CoveragePercent: 0,
			Tool:            "go test",
			ErrorMessage:    "errors in go test",
		}
	}

	coverCmd := exec.Command("go", "tool", "cover", "-func", coverProfile)
	coverCmd.Dir = repoPath
	var coverOut bytes.Buffer
	coverCmd.Stdout = &coverOut
	coverCmd.Stderr = &coverOut
	if err := coverCmd.Run(); err != nil {
		return types.TestCoverageResult{
			Status:          types.ResultStatusWarning,
			CoveragePercent: 0,
			Tool:            "go tool cover",
			ErrorMessage:    "errors in go test",
		}
	}

	lines := strings.Split(strings.TrimSpace(coverOut.String()), "\n")
	var totalLine string
	if len(lines) > 0 {
		totalLine = lines[len(lines)-1]
	}
	var percent float64 = 0
	if idx := strings.LastIndex(totalLine, "\t"); idx != -1 {
		pctStr := strings.TrimSuffix(strings.TrimSpace(totalLine[idx+1:]), "%")
		pctStr = strings.ReplaceAll(pctStr, ",", "")
		if p, err := strconv.ParseFloat(pctStr, 64); err == nil {
			percent = p
		}
	}

	status := types.ResultStatusPassed
	return types.TestCoverageResult{
		Status:          status,
		CoveragePercent: percent,
		Tool:            "go test",
	}
}
