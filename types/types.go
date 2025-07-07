package types

import (
	"github.com/ptk1729/verifier_service/vulnscan"
)

type Metadata struct {
	ProjectName     string `json:"project_name"`
	RepoURL         string `json:"repo_url"`
	CommitID        string `json:"commit_id"`
	CheckedAt       string `json:"checked_at"`
	VerifierVersion string `json:"verifier_version"`
	RunID           string `json:"run_id"`
}

type VulnerabilityCheck struct {
	Status          vulnscan.ResultStatus `json:"status"`
	Tool            string                `json:"tool"` // osv-scanner, gosec, etc.
	Vulnerabilities []vulnscan.OsvFinding `json:"vulnerabilities"`
}

type CommitCheck struct {
	Commit   string `json:"commit"`
	Author   string `json:"author"`
	KeyID    string `json:"key_id"`
	Verified bool   `json:"verified"`
}

type CommitVerification struct {
	Status              ResultStatus  `json:"status"`
	CommitsChecked      []CommitCheck `json:"commits_checked"`
	NoVerifiedCommits   int           `json:"no_verified_commits"`
	NoUnverifiedCommits int           `json:"no_unverified_commits"`
}

// ResultStatus is a common type for status results across all packages
type ResultStatus = vulnscan.ResultStatus

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)
