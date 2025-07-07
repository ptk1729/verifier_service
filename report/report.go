package report

import (
	"time"

	"github.com/ptk1729/verifier_service/commit"
	"github.com/ptk1729/verifier_service/customchecks"
	"github.com/ptk1729/verifier_service/envcheck"
	"github.com/ptk1729/verifier_service/formatting"
	"github.com/ptk1729/verifier_service/linting"
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
}

// GenerateReport generates a complete verification report for the given repository
func GenerateReport(
	projectName string,
	repoURL string,
	clonePath string,
	verifierVersion string,
	requiredReviews int,
	allowedKeys []string,
) Report {
	// Get commit information
	commitID := utils.GetLatestCommit(clonePath)
	runID := utils.RandomUUID()
	now := time.Now().UTC().Format(time.RFC3339)

	// Run all checks
	lintingResult := linting.RunGolint(clonePath)
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

	return Report{
		MetaData: types.Metadata{
			ProjectName:     projectName,
			RepoURL:         repoURL,
			CommitID:        commitID,
			CheckedAt:       now,
			VerifierVersion: verifierVersion,
			RunID:           runID,
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
	}
}
