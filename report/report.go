package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/ptk1729/verifier_service/commit"
	"github.com/ptk1729/verifier_service/envcheck"
	"github.com/ptk1729/verifier_service/formatting"
	"github.com/ptk1729/verifier_service/linting"
	"github.com/ptk1729/verifier_service/manifest"
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
	SlsaCheck          slsa.SlsaCheckResult        `json:"slsa_check"`
	ManifestScan       types.ManifestScanResult    `json:"manifest_scan"`
	Timing             types.TimingResults         `json:"timing"`
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

func calculateReportHash2(data interface{}) (string, string, error) {
	// Marshal to generic map
	raw, err := json.Marshal(data)
	if err != nil {
		return "", "", err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}

	repAny, ok := m["report"]
	if !ok {
		return "", "", nil // no report
	}
	rep, ok := repAny.(map[string]interface{})
	if !ok {
		return "", "", nil
	}

	// Sort keys
	keys := make([]string, 0, len(rep))
	for k := range rep {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	cleaner := regexp.MustCompile(`[\s\r\n\t]+`)

	var sb strings.Builder
	for _, k := range keys {
		// key stripped
		sb.WriteString(cleaner.ReplaceAllString(k, ""))

		// value compact + stripped
		valBytes, err := json.Marshal(rep[k])
		if err != nil {
			return "", "", err
		}
		valStr := cleaner.ReplaceAllString(string(valBytes), "")
		sb.WriteString(valStr)
	}

	compactReport := sb.String()
	sum := sha256.Sum256([]byte(compactReport))
	return compactReport, hex.EncodeToString(sum[:]), nil
}

// zero-copy convert []byte to string
func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b)) // if you prefer safe: return string(b)
}

// timeCheck measures the execution time and memory usage of a function
func timeCheck(checkName string, fn func()) types.TimingInfo {
	var m1, m2 runtime.MemStats
	runtime.GC() // Force garbage collection before measurement
	runtime.ReadMemStats(&m1)

	start := time.Now()
	fn()
	duration := time.Since(start)

	runtime.ReadMemStats(&m2)

	return types.TimingInfo{
		CheckName:    checkName,
		Duration:     duration.Milliseconds(),         // Convert to milliseconds
		MemoryBefore: m1.Alloc / 1024,                 // Convert to KB
		MemoryAfter:  m2.Alloc / 1024,                 // Convert to KB
		MemoryDelta:  int64(m2.Alloc-m1.Alloc) / 1024, // Convert to KB
	}
}

// func calculateReportHash(data ReportData) (string, error) {
//
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

	// Variables to store results
	var lintingResult linting.LintingResult
	var formattingResult formatting.FormattingResult
	var vulnStatus vulnscan.ResultStatus
	var vulnTool string
	var vulnerabilities []vulnscan.OsvFinding
	var commitVerification types.CommitVerification
	var envResult envcheck.EnvVariablesResult
	var manifestResult types.ManifestScanResult
	var slsaResult slsa.SlsaCheckResult

	// Timing measurements
	var timingResults []types.TimingInfo
	overallStart := time.Now()

	// Run all checks with timing
	timingResults = append(timingResults, timeCheck("linting", func() {
		lintingResult = linting.RunLint(clonePath)
	}))

	timingResults = append(timingResults, timeCheck("formatting", func() {
		formattingResult = formatting.RunGofmt(clonePath)
	}))

	timingResults = append(timingResults, timeCheck("vulnerability_scan", func() {
		vulnStatus, vulnTool, vulnerabilities = vulnscan.RunOsvScanner(clonePath)
	}))

	// Enrich vulnerabilities with severity
	if len(vulnerabilities) > 0 {
		timingResults = append(timingResults, timeCheck("vulnerability_enrichment", func() {
			vulnerabilities = vulnscan.EnrichVulnerabilitiesWithSeverity(vulnerabilities)
		}))
	}

	timingResults = append(timingResults, timeCheck("commit_verification", func() {
		commitVerification = commit.VerifyCommits(clonePath, allowedKeys)
	}))

	timingResults = append(timingResults, timeCheck("env_check", func() {
		envResult = envcheck.ScanEnvFiles(clonePath)
	}))

	timingResults = append(timingResults, timeCheck("manifest_scan", func() {
		manifestResult = manifest.ScanManifests(clonePath)
	}))

	timingResults = append(timingResults, timeCheck("slsa_check", func() {
		slsaResult = slsa.RunSlsaCheck(context.Background(), slsaBinaryPath, slsaProvenancePath, slsaSourceURI)
	}))

	// Calculate total time
	totalTime := time.Since(overallStart)
	timingData := types.TimingResults{
		Results: timingResults,
		Total:   totalTime.Milliseconds(), // Convert to milliseconds
	}

	// Print timing results
	fmt.Println("\n=== TIMING RESULTS ===")
	for _, timing := range timingResults {
		fmt.Printf("%-25s: %dms (Memory: %+d KB)\n",
			timing.CheckName,
			timing.Duration,
			timing.MemoryDelta)
	}
	fmt.Printf("%-25s: %dms\n", "TOTAL", totalTime.Milliseconds())
	fmt.Println("=======================\n")

	var verificationStatus types.ResultStatus = types.ResultStatusPassed

	verificationStatus = overallStatus(
		lintingResult.Status,
		formattingResult.Status,
		vulnStatus,
		commitVerification.Status,
		envResult.Status,
		slsaResult.Status,
		manifestResult.Status,
	)

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
		SlsaCheck:          slsaResult,
		ManifestScan:       manifestResult,
		Timing:             timingData,
	}

	reportDataJSON, err := json.Marshal(reportData)
	if err != nil {
		return Report{}, err
	}
	reportData = ReportData{}
	err = json.Unmarshal(reportDataJSON, &reportData)
	if err != nil {
		return Report{}, err
	}
	r := Report{Data: reportData}
	_, reportHash2, err := calculateReportHash2(r)
	// reportString, reportHash2, err := calculateReportHash2(reportData)
	if err != nil {
		return Report{}, err
	}
	// fmt.Println("reportString: ", reportString)
	fmt.Printf("Calculated SHA256: %s\n\n", reportHash2)
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
		// ReportString: reportString,
		ReportSHA256: reportHash2,
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
		if status == types.ResultStatusFailed {
			return types.ResultStatusFailed
		}
	}
	return types.ResultStatusPassed
}
