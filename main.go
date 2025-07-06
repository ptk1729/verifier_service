package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil" // Added for API calls
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ptk1729/verifier_service/vulnscan"
	// "github.com/ptk1729/verifier_service/commit"
)

type Metadata struct {
	ProjectName     string `json:"project_name"`
	RepoURL         string `json:"repo_url"`
	CommitID        string `json:"commit_id"`
	CheckedAt       string `json:"checked_at"`
	VerifierVersion string `json:"verifier_version"`
	RunID           string `json:"run_id"`
}

type Linting struct {
	Status   ResultStatus `json:"status"`
	Errors   []string     `json:"errors"`
	Warnings []string     `json:"warnings"`
	Tool     string       `json:"tool"`
}

type Formatting struct {
	Status       ResultStatus `json:"status"`
	Tool         string       `json:"tool"`
	FilesChanged []string     `json:"files_changed"`
}

type VulnerabilityCheck struct {
	Status          vulnscan.ResultStatus `json:"status"`
	Tool            string                `json:"tool"` // osv-scanner, gosec, etc.
	Vulnerabilities []vulnscan.OsvFinding `json:"vulnerabilities"`
}

// struct for type of results (FAILED, WARNING, PASSED)
type ResultStatus = vulnscan.ResultStatus

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

type CommitCheck struct {
	Commit   string `json:"commit"`
	Author   string `json:"author"`
	KeyID    string `json:"key_id"`
	Verified bool   `json:"verified"`
}

type CommitVerification struct {
	Status         ResultStatus  `json:"status"`
	CommitsChecked []CommitCheck `json:"commits_checked"`
}

type ReviewDetail struct {
	Reviewer string `json:"reviewer"`
	Approved bool   `json:"approved"`
}

type ReviewsCheck struct {
	Status          ResultStatus   `json:"status"`
	RequiredReviews int            `json:"required_reviews"`
	ActualReviews   int            `json:"actual_reviews"`
	Details         []ReviewDetail `json:"details"`
}

type EnvIssue struct {
	File     string `json:"file"`
	Variable string `json:"variable"`
	Problem  string `json:"problem"`
}

type EnvVariablesCheck struct {
	Status ResultStatus `json:"status"`
	Issues []EnvIssue   `json:"issues"`
}

type CustomCheck struct {
	Name    string        `json:"name"`
	Status  ResultStatus  `json:"status"`
	Details []interface{} `json:"details"`
}

type Report struct {
	MetaData           Metadata           `json:"metadata"`
	Linting            Linting            `json:"linting"`
	Formatting         Formatting         `json:"formatting"`
	VulnerabilityCheck VulnerabilityCheck `json:"vulnerability_check"`
	CommitVerification CommitVerification `json:"commit_verification"`
	ReviewsCheck       ReviewsCheck       `json:"reviews_check"`
	EnvVariablesCheck  EnvVariablesCheck  `json:"env_variables_check"`
	CustomChecks       []CustomCheck      `json:"custom_checks"`
}

func main() {
	// -------- SETUP --------
	// get repo url from command line
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <repo_url>")
		os.Exit(1)
	}
	//  add an optional flag to print the report to the console
	printReport := false
	if len(os.Args) > 2 && os.Args[2] == "--print-report" {
		printReport = true
	}
	repoURL := os.Args[1]
	// repoURL := "https://github.com/ptk1729/go_proj"
	projectName := "go_proj"
	clonePath := "./repo_clone"
	verifierVersion := "1.0.0"
	requiredReviews := 2

	// -------- CLONE --------
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		os.RemoveAll(clonePath)
	}
	run("git", "clone", repoURL, clonePath)

	// -------- COMMIT INFO --------
	commitID := getLatestCommit(clonePath)
	// authorEmail := getCommitAuthor(clonePath, commitID)
	// keyID := "FAKE123456"
	// verified := true

	// -------- RUN ID --------
	runID := randomUUID()

	// -------- TIME --------
	now := time.Now().UTC().Format(time.RFC3339)

	// -------- LINTING --------
	lintWarnings, lintErrors := runGolint(clonePath)
	lintStatus := ResultStatusPassed
	if len(lintErrors) > 0 {
		lintStatus = ResultStatusFailed
	} else if len(lintWarnings) > 0 {
		lintStatus = ResultStatusWarning
	}

	// -------- FORMATTING --------
	filesChanged := runGofmt(clonePath)
	formattingStatus := ResultStatusPassed
	if len(filesChanged) > 0 {
		formattingStatus = ResultStatusPassed
	} else {
		formattingStatus = ResultStatusPassed // Gofmt may not change anything
	}

	// -------- VULN CHECK --------
	vulnStatus, vulnTool, vulnerabilities := vulnscan.RunOsvScanner(clonePath)
	fmt.Println("Vulnerability check:", vulnStatus, "Tool:", vulnTool, "Found", len(vulnerabilities), "initial vulnerabilities.")

	// -------- ENRICH VULNERABILITIES WITH SEVERITY --------
	if len(vulnerabilities) > 0 {
		vulnerabilities = vulnscan.EnrichVulnerabilitiesWithSeverity(vulnerabilities)
	}

	// -------- REVIEWS (Dummy) --------
	reviews := []ReviewDetail{
		{Reviewer: "bob@example.com", Approved: true},
	}
	reviewsStatus := ResultStatusFailed
	if len(reviews) >= requiredReviews {
		reviewsStatus = ResultStatusPassed
	}

	// -------- ENV CHECK --------
	envIssues := scanEnvFile(clonePath)
	envStatus := ResultStatusPassed
	if len(envIssues) > 0 {
		envStatus = ResultStatusWarning
	}

	// -------- CUSTOM CHECKS (Dummy Dockerfile) --------
	dockerStatus := ResultStatusPassed
	dockerDetails := []interface{}{}
	if _, err := os.Stat(filepath.Join(clonePath, "Dockerfile")); err != nil {
		dockerStatus = "SKIPPED"
	}

	// -------- COMMIT VERIFICATION --------
	// allowedKeys := []string{"FAKE123456"} // TODO: Replace with real allowed key IDs
	// commitVerification := commit.VerifyCommits(clonePath, allowedKeys)

	// -------- BUILD REPORT --------
	report := Report{
		MetaData: Metadata{
			ProjectName:     projectName,
			RepoURL:         repoURL,
			CommitID:        commitID,
			CheckedAt:       now,
			VerifierVersion: verifierVersion,
			RunID:           runID,
		},
		Linting: Linting{
			Status:   lintStatus,
			Errors:   lintErrors,
			Warnings: lintWarnings,
			Tool:     "golint",
		},
		Formatting: Formatting{
			Status:       formattingStatus,
			Tool:         "gofmt",
			FilesChanged: filesChanged,
		},
		VulnerabilityCheck: VulnerabilityCheck{
			Status:          vulnStatus,
			Tool:            vulnTool,
			Vulnerabilities: vulnerabilities,
		},
		// CommitVerification: commitVerification,
		ReviewsCheck: ReviewsCheck{
			Status:          reviewsStatus,
			RequiredReviews: requiredReviews,
			ActualReviews:   len(reviews),
			Details:         reviews,
		},
		EnvVariablesCheck: EnvVariablesCheck{
			Status: envStatus,
			Issues: envIssues,
		},
		CustomChecks: []CustomCheck{
			{
				Name:    "Dockerfile Best Practices",
				Status:  dockerStatus,
				Details: dockerDetails,
			},
		},
	}

	// -------- SAVE --------
	reportName := fmt.Sprintf("/tmp/report_%s.json", time.Now().Format("20060102150405"))
	saveJSON(report, reportName)

	fmt.Printf("Done. Report saved to %s\n", reportName)
	if printReport {
		reportJSON, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(reportJSON))
	}
}

func run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func getLatestCommit(path string) string {
	out := run("git", "-C", path, "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func getCommitAuthor(path, commit string) string {
	out := run("git", "-C", path, "show", "-s", "--format=%ae", commit)
	return strings.TrimSpace(out)
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

func randomUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func saveJSON(data interface{}, filename string) {
	file, _ := json.MarshalIndent(data, "", "  ")
	ioutil.WriteFile(filename, file, 0644)
}
