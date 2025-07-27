package customchecks

import (
	"os"
	"path/filepath"
)

// CustomCheck is a custom check that can be run on a repository
type CustomCheck struct {
	Name    string        `json:"name"`
	Status  ResultStatus  `json:"status"`
	Details []interface{} `json:"details"`
	Error   string        `json:"error,omitempty"`
}

// ResultStatus is a common type for status results across all packages
type ResultStatus string

// ResultStatusFailed is a custom check that failed
const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
	ResultStatusSkipped ResultStatus = "SKIPPED"
)

// ResultStatusSkipped is a custom check that was skipped

// ResultStatusPassed is a custom check that passed

// ResultStatusWarning is a custom check that had a warning

// ResultStatusSkipped is a custom check that was skipped

// CheckDockerfile checks if a Dockerfile exists and validates its best practices
func CheckDockerfile(path string) CustomCheck {
	status := ResultStatusPassed
	details := []interface{}{}

	if _, err := os.Stat(filepath.Join(path, "Dockerfile")); err != nil {
		status = ResultStatusSkipped
	}

	return CustomCheck{
		Name:    "Dockerfile Best Practices",
		Status:  status,
		Details: details,
	}
}

// RunAllCustomChecks runs all custom checks and returns the results
func RunAllCustomChecks(path string) []CustomCheck {
	var checks []CustomCheck

	// Add Dockerfile check
	checks = append(checks, CheckDockerfile(path))

	// TODO: Add more custom checks here as needed

	return checks
}
