package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/ptk1729/verifier_service/commit"
	"github.com/ptk1729/verifier_service/customchecks"
	"github.com/ptk1729/verifier_service/envcheck"
	"github.com/ptk1729/verifier_service/formatting"
	"github.com/ptk1729/verifier_service/linting"
	"github.com/ptk1729/verifier_service/slsa"
	"github.com/ptk1729/verifier_service/types"
	"github.com/ptk1729/verifier_service/utils"
	"github.com/ptk1729/verifier_service/vulnscan"
)

// ReportData contains all the verification results
type ReportData struct {
	Linting            linting.LintingResult       `json:"linting"`
	Formatting         formatting.FormattingResult `json:"formatting"`
	VulnerabilityCheck types.VulnerabilityCheck    `json:"vulnerability_check"`
	CommitVerification types.CommitVerification    `json:"commit_verification"`
	EnvVariablesCheck  envcheck.EnvVariablesResult `json:"env_variables_check"`
	CustomChecks       []customchecks.CustomCheck  `json:"custom_checks"`
	SlsaCheck          slsa.SlsaCheckResult        `json:"slsa_check"`
}

// Report is the main struct for the report with metadata containing SHA256 hash
type Report struct {
	Metadata types.MetadataWithHash `json:"metadata"`
	Data     ReportData             `json:"report"`
}

// calculateReportHash calculates SHA256 hash of the report data

func calculateReportHash(data ReportData) (string, error) {
	// Use Marshal (not MarshalIndent) to get compact JSON without formatting
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Additional safety: remove any potential whitespace/newlines
	compactJSON := strings.ReplaceAll(string(jsonData), " ", "")
	compactJSON = strings.ReplaceAll(compactJSON, "\n", "")
	compactJSON = strings.ReplaceAll(compactJSON, "\r", "")
	compactJSON = strings.ReplaceAll(compactJSON, "\t", "")

	hash := sha256.Sum256([]byte(compactJSON))
	return hex.EncodeToString(hash[:]), nil
}

// func calculateReportHash(data ReportData) (string, error) {
// 	// Use MarshalIndent to match the formatting used by jq and SaveJSON
// 	jsonData, err := json.MarshalIndent(data, "", "  ")
// 	if err != nil {
// 		return "", err
// 	}

// 	hash := sha256.Sum256(jsonData)
// 	return hex.EncodeToString(hash[:]), nil
// }

// GenerateReport generates a complete verification report for the given repository
func GenerateReport(
	projectName string,
	repoURL string,
	clonePath string,
	verifierVersion string,
	requiredReviews int,
	allowedKeys []string,
	slsaBinaryPath string,
	slsaProvenancePath string,
	slsaSourceURI string,
) (Report, error) {
	// Get commit information
	commitHash := utils.GetLatestCommit(clonePath)
	commitMessage := utils.GetLatestCommitMessage(clonePath)
	runID := utils.RandomUUID()
	now := time.Now().UTC().Format(time.RFC3339)

	// Run all checks
	lintingResult := linting.RunLint(clonePath)
	formattingResult := formatting.RunGofmt(clonePath)
	vulnStatus, vulnTool, vulnerabilities := vulnscan.RunOsvScanner(clonePath)

	// Enrich vulnerabilities with severity
	if len(vulnerabilities) > 0 {
		vulnerabilities = vulnscan.EnrichVulnerabilitiesWithSeverity(vulnerabilities)
	}

	// Run commit verification
	commitVerification := commit.VerifyCommits(clonePath, allowedKeys)

	envResult := envcheck.ScanEnvFiles(clonePath)
	customChecks := customchecks.RunAllCustomChecks(clonePath)

	// Run SLSA check
	slsaResult := slsa.RunSlsaCheck(context.Background(), slsaBinaryPath, slsaProvenancePath, slsaSourceURI)

	var verificationStatus types.ResultStatus = types.ResultStatusPassed

	var customStatuses []customchecks.ResultStatus
	for _, check := range customChecks {
		customStatuses = append(customStatuses, check.Status)
	}
	verificationStatus = overallStatus(
		lintingResult.Status,
		formattingResult.Status,
		vulnStatus,
		commitVerification.Status,
		envResult.Status,
		slsaResult.Status,
		customStatuses,
	)

	// Create report data
	reportData := ReportData{
		Linting:    lintingResult,
		Formatting: formattingResult,
		VulnerabilityCheck: types.VulnerabilityCheck{
			Status:          vulnStatus,
			Tool:            vulnTool,
			Vulnerabilities: vulnerabilities,
		},
		CommitVerification: commitVerification,
		EnvVariablesCheck:  envResult,
		CustomChecks:       customChecks,
		SlsaCheck:          slsaResult,
	}

	// Calculate SHA256 hash of the report data
	reportHash, err := calculateReportHash(reportData)
	if err != nil {
		return Report{}, err
	}

	// Create metadata with hash
	metadata := types.MetadataWithHash{
		Metadata: types.Metadata{
			ProjectName:        projectName,
			RepoURL:            repoURL,
			CommitHash:         commitHash,
			CommitMessage:      commitMessage,
			CheckedAt:          now,
			VerifierVersion:    verifierVersion,
			RunID:              runID,
			VerificationStatus: verificationStatus,
		},
		ReportSHA256: reportHash,
	}

	return Report{
		Metadata: metadata,
		Data:     reportData,
	}, nil
}

// extractProvenanceFileNames extracts just the file names from SLSA check results
func extractProvenanceFileNames(checks []types.SLSACheck) []string {
	var fileNames []string
	for _, check := range checks {
		fileNames = append(fileNames, check.ProvenanceFiles...)
	}
	return fileNames
}

func overallStatus(statuses ...interface{}) types.ResultStatus {
	for _, status := range statuses {
		if status == types.ResultStatusFailed || status == customchecks.ResultStatusSkipped {
			return types.ResultStatusFailed
		}
	}
	return types.ResultStatusPassed
}
