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
	Status ResultStatus `json:"status"`
	// CommitsChecked      []CommitCheck `json:"commits_checked"`
	NoVerifiedCommits   int `json:"no_verified_commits"`
	NoUnverifiedCommits int `json:"no_unverified_commits"`
}

// SLSACheck represents the result of scanning SLSAs
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

// ManifestScanResult represents the result of scanning manifests
type ManifestScanResult struct {
	Status              string                   `json:"status"`
	Tool                string                   `json:"tool"`
	Dockerfiles         []DockerfileInfo         `json:"dockerfiles"`
	KubernetesManifests []KubernetesManifestInfo `json:"kubernetes_manifests"`
	TotalFiles          int                      `json:"total_files"`
	FilesWithIssues     int                      `json:"files_with_issues"`
}

// DockerfileInfo contains information about a Dockerfile
type DockerfileInfo struct {
	Path            string       `json:"path"`
	ExposedPorts    []PortInfo   `json:"exposed_ports"`
	EnvironmentVars []EnvVarInfo `json:"environment_variables"`
	HasIssues       bool         `json:"has_issues"`
	Issues          []string     `json:"issues,omitempty"`
}

// KubernetesManifestInfo contains information about a Kubernetes manifest
type KubernetesManifestInfo struct {
	Path            string       `json:"path"`
	Kind            string       `json:"kind"`
	Name            string       `json:"name"`
	ExposedPorts    []PortInfo   `json:"exposed_ports"`
	EnvironmentVars []EnvVarInfo `json:"environment_variables"`
	HasIssues       bool         `json:"has_issues"`
	Issues          []string     `json:"issues,omitempty"`
}

// PortInfo represents port information
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"` // "exposed", "service", "container"
}

// EnvVarInfo represents environment variable information
type EnvVarInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"` // "env", "envFrom", "configMap", "secret"
}

// TimingInfo represents timing information for a specific check
type TimingInfo struct {
	CheckName    string `json:"check_name"`
	Duration     int64  `json:"duration_ms"` // Duration in milliseconds
	MemoryBefore uint64 `json:"memory_before_kb"`
	MemoryAfter  uint64 `json:"memory_after_kb"`
	MemoryDelta  int64  `json:"memory_delta_kb"`
}

// TimingResults contains all timing information for the verification process
type TimingResults struct {
	Results []TimingInfo `json:"timing_results"`
	Total   int64        `json:"total_duration_ms"` // Total duration in milliseconds
}

// TestCoverageResult represents the result of running `go test` with coverage
type TestCoverageResult struct {
	Status          ResultStatus `json:"status"`
	CoveragePercent float64      `json:"coverage_percent"`
	Tool            string       `json:"tool"`
	ErrorMessage    string       `json:"error_message,omitempty"`
}
