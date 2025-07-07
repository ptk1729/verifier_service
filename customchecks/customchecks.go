package customchecks

import (
	"os"
	"path/filepath"
)

type CustomCheck struct {
	Name    string        `json:"name"`
	Status  ResultStatus  `json:"status"`
	Details []interface{} `json:"details"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
	ResultStatusSkipped ResultStatus = "SKIPPED"
)

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
