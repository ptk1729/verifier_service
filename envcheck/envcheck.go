package envcheck

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"slices"
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
		// Check if any issues contain sensitive keywords (FAILED status)
		hasSensitiveIssues := false
		for _, issue := range issues {
			if strings.Contains(issue.Problem, "SENSITIVE:") {
				hasSensitiveIssues = true
				break
			}
		}

		if hasSensitiveIssues {
			status = ResultStatusFailed
		} else {
			status = ResultStatusWarning
		}
	}

	return EnvVariablesResult{
		Status: status,
		Issues: issues,
	}
}

// scanEnvFile scans for all environment files and returns all keys found
// If any keys contain sensitive words, they will be marked as FAILED issues
func scanEnvFile(path string) []EnvIssue {
	var issues []EnvIssue

	// Define common environment file patterns
	envFilePatterns := []string{".env", ".env.local", ".env.development", ".env.production", ".env.test"}

	// Define sensitive keywords that should trigger FAILED status
	sensitiveKeywords := []string{
		"SECRET", "KEY", "PASSWORD", "PASS", "PWD", "TOKEN", "AUTH",
		"CREDENTIAL", "CRED", "PRIVATE", "PRIV", "API_KEY", "APIKEY",
		"ACCESS_KEY", "SECRET_KEY", "PRIVATE_KEY", "DATABASE_PASSWORD",
		"DB_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD",
		"AWS_SECRET", "AWS_KEY", "GITHUB_TOKEN", "JWT_SECRET", "SESSION_SECRET",
		"ENCRYPTION_KEY", "SIGNING_KEY", "MASTER_KEY", "ROOT_PASSWORD",
	}

	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Check if this is an environment file
		fileName := filepath.Base(p)
		isEnvFile := slices.Contains(envFilePatterns, fileName)

		if isEnvFile {
			fmt.Println("Scanning env file: ", p)
			data, err := ioutil.ReadFile(p)
			if err != nil {
				return nil // Skip files we can't read
			}

			lines := strings.Split(string(data), "\n")
			for lineNum, line := range lines {
				line = strings.TrimSpace(line)

				// Skip empty lines and comments
				if line == "" {
					continue
				}

				// Check if line contains an environment variable assignment
				if strings.Contains(line, "=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						fmt.Println("Key: ", key)
						// Only add if key is not empty
						if key != "" {
							// Check if the key contains any sensitive keywords
							upperKey := strings.ToUpper(key)
							isSensitive := false
							matchedKeyword := ""

							for _, keyword := range sensitiveKeywords {
								if strings.Contains(upperKey, strings.ToUpper(keyword)) {
									isSensitive = true
									matchedKeyword = keyword
									break
								}
							}

							var problem string
							if isSensitive {
								problem = fmt.Sprintf("SENSITIVE: Environment variable contains sensitive keyword '%s' (line %d): %s",
									matchedKeyword, lineNum+1, key)
							} else {
								problem = fmt.Sprintf("Environment variable found (line %d): %s", lineNum+1, key)
							}

							issues = append(issues, EnvIssue{
								File:     fileName,
								Variable: key,
								Problem:  problem,
							})
						}
					}
				}
			}
		}
		return nil
	})

	return issues
}
