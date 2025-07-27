package report

import (
	"context"
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

type Report struct {
	MetaData           types.Metadata              `json:"metadata"`
	Linting            linting.LintingResult       `json:"linting"`
	Formatting         formatting.FormattingResult `json:"formatting"`
	VulnerabilityCheck types.VulnerabilityCheck    `json:"vulnerability_check"`
	CommitVerification types.CommitVerification    `json:"commit_verification"`
	// ReviewsCheck       reviews.ReviewsResult       `json:"reviews_check"` TODO: removing for now, low priority
	EnvVariablesCheck envcheck.EnvVariablesResult `json:"env_variables_check"`
	CustomChecks      []customchecks.CustomCheck  `json:"custom_checks"`
	// SLSACheck         types.SLSACheck             `json:"slsa_check"`
	SlsaCheck slsa.SlsaCheckResult `json:"slsa_check"`
}

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
) Report {
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

	// reviewsResult := reviews.CheckReviews(requiredReviews)
	envResult := envcheck.ScanEnvFiles(clonePath)
	customChecks := customchecks.RunAllCustomChecks(clonePath)

	// Run SLSA check
	slsaResult := slsa.RunSlsaCheck(context.Background(), slsaBinaryPath, slsaProvenancePath, slsaSourceURI)

	var verificationStatus types.ResultStatus = types.ResultStatusPassed
	// if any check is failed, the verification status is failed
	// if any check is skipped, the verification status is failed
	// if all checks are passed, the verification status is passed

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

	return Report{
		MetaData: types.Metadata{
			ProjectName:        projectName,
			RepoURL:            repoURL,
			CommitHash:         commitHash,
			CommitMessage:      commitMessage,
			CheckedAt:          now,
			VerifierVersion:    verifierVersion,
			RunID:              runID,
			VerificationStatus: verificationStatus,
		},
		Linting:    lintingResult,
		Formatting: formattingResult,
		VulnerabilityCheck: types.VulnerabilityCheck{
			Status:          vulnStatus,
			Tool:            vulnTool,
			Vulnerabilities: vulnerabilities,
		},
		CommitVerification: commitVerification,
		// ReviewsCheck:       reviewsResult,
		EnvVariablesCheck: envResult,
		CustomChecks:      customChecks,
		SlsaCheck:         slsaResult,
	}
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
