package types

import (
	"github.com/ptk1729/verifier_service/vulnscan"
)

type Metadata struct {
	ProjectName        string       `json:"project_name"`
	RepoURL            string       `json:"repo_url"`
	CommitHash         string       `json:"commit_hash"`
	CommitMessage      string       `json:"commit_message"`
	CheckedAt          string       `json:"checked_at"`
	VerifierVersion    string       `json:"verifier_version"`
	RunID              string       `json:"run_id"`
	VerificationStatus ResultStatus `json:"verification_status"`
}

// MetadataWithHash extends Metadata with a SHA256 hash of the report
type MetadataWithHash struct {
	Metadata
	ReportSHA256 string `json:"report_sha256"`
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

type SLSACheck struct {
	Status            ResultStatus `json:"status"`
	ProvenanceFiles   []string     `json:"provenance_files"`
	TotalFiles        int          `json:"total_files"`
	ValidFiles        int          `json:"valid_files"`
	InvalidFiles      int          `json:"invalid_files"`
	MissingProvenance bool         `json:"missing_provenance"`
	SLSALevel         string       `json:"slsa_level"`
	BuilderID         string       `json:"builder_id,omitempty"`
	ErrorMessage      string       `json:"error_message,omitempty"`
}

// ResultStatus is a common type for status results across all packages
type ResultStatus = vulnscan.ResultStatus

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)
