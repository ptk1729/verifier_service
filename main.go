package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ptk1729/verifier_service/commit"
	"github.com/ptk1729/verifier_service/customchecks"
	"github.com/ptk1729/verifier_service/envcheck"
	"github.com/ptk1729/verifier_service/formatting"
	"github.com/ptk1729/verifier_service/linting"
	"github.com/ptk1729/verifier_service/report"
	"github.com/ptk1729/verifier_service/utils"
	"github.com/ptk1729/verifier_service/vulnscan"
)

func main() {
	// Define flags for individual checks
	var (
		lintFlag        = flag.Bool("lint", false, "Run only linting check")
		formatFlag      = flag.Bool("format", false, "Run only formatting check")
		vulnFlag        = flag.Bool("vuln", false, "Run only vulnerability check")
		envFlag         = flag.Bool("env", false, "Run only environment variables check")
		reviewsFlag     = flag.Bool("reviews", false, "Run only reviews check")
		customFlag      = flag.Bool("custom", false, "Run only custom checks")
		commitFlag      = flag.Bool("commit", false, "Run only commit verification check")
		printReportFlag = flag.Bool("print-report", false, "Print the full report to console")
		requiredReviews = flag.Int("required-reviews", 2, "Number of required reviews")
		allowedKeys     = flag.String("allowed-keys", "", "Comma-separated list of allowed GPG key IDs for commit verification")
	)

	flag.Parse()

	// Check if any individual check flag is set
	individualCheck := *lintFlag || *formatFlag || *vulnFlag || *envFlag || *reviewsFlag || *customFlag || *commitFlag

	// Get repo URL from positional arguments
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: go run main.go [flags] <repo_url>")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go https://github.com/user/repo")
		fmt.Println("  go run main.go -lint https://github.com/user/repo")
		fmt.Println("  go run main.go -vuln https://github.com/user/repo")
		fmt.Println("  go run main.go -commit -allowed-keys=ABC123,DEF456 https://github.com/user/repo")
		fmt.Println("  go run main.go -print-report https://github.com/user/repo")
		os.Exit(1)
	}

	repoURL := args[0]
	projectName := "go_proj"
	clonePath := "./repo_clone"
	verifierVersion := "1.0.0"

	// Parse allowed keys
	var allowedKeysList []string
	if *allowedKeys != "" {
		allowedKeysList = strings.Split(*allowedKeys, ",")
		for i, key := range allowedKeysList {
			allowedKeysList[i] = strings.TrimSpace(key)
		}
	}

	// -------- CLONE --------
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		os.RemoveAll(clonePath)
	}
	utils.Run("git", "clone", repoURL, clonePath)

	if individualCheck {
		// Run individual check based on flag
		runIndividualCheck(clonePath, *lintFlag, *formatFlag, *vulnFlag, *envFlag, *reviewsFlag, *customFlag, *commitFlag, *requiredReviews, allowedKeysList)
	} else {
		// Run full report generation
		verificationReport := report.GenerateReport(
			projectName,
			repoURL,
			clonePath,
			verifierVersion,
			*requiredReviews,
			allowedKeysList,
		)

		// -------- SAVE --------
		reportName := fmt.Sprintf("/tmp/report_%s.json", time.Now().Format("20060102150405"))
		utils.SaveJSON(verificationReport, reportName)

		fmt.Printf("Done. Report saved to %s\n", reportName)
		if *printReportFlag {
			reportJSON, _ := json.MarshalIndent(verificationReport, "", "  ")
			fmt.Println(string(reportJSON))
		}
	}
}

func runIndividualCheck(clonePath string, lint, format, vuln, env, reviewsFlag, custom, commitFlag bool, requiredReviews int, allowedKeys []string) {
	if lint {
		fmt.Println("=== LINTING CHECK ===")
		result := linting.RunGolint(clonePath)
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	}

	if format {
		fmt.Println("=== FORMATTING CHECK ===")
		result := formatting.RunGofmt(clonePath)
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	}

	if vuln {
		fmt.Println("=== VULNERABILITY CHECK ===")
		status, tool, vulnerabilities := vulnscan.RunOsvScanner(clonePath)
		fmt.Printf("Status: %s\n", status)
		fmt.Printf("Tool: %s\n", tool)
		fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))

		if len(vulnerabilities) > 0 {
			vulnerabilities = vulnscan.EnrichVulnerabilitiesWithSeverity(vulnerabilities)
			output, _ := json.MarshalIndent(vulnerabilities, "", "  ")
			fmt.Println("Vulnerabilities:")
			fmt.Println(string(output))
		}
	}

	if env {
		fmt.Println("=== ENVIRONMENT VARIABLES CHECK ===")
		result := envcheck.ScanEnvFiles(clonePath)
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	}

	// if reviewsFlag {
	// 	fmt.Println("=== REVIEWS CHECK ===")
	// 	result := reviews.CheckReviews(requiredReviews)
	// 	output, _ := json.MarshalIndent(result, "", "  ")
	// 	fmt.Println(string(output))
	// }

	if custom {
		fmt.Println("=== CUSTOM CHECKS ===")
		checks := customchecks.RunAllCustomChecks(clonePath)
		output, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(output))
	}

	if commitFlag {
		fmt.Println("=== COMMIT VERIFICATION CHECK ===")
		if len(allowedKeys) == 0 {
			fmt.Println("Warning: No allowed keys specified. Use -allowed-keys flag to specify allowed GPG key IDs.")
			fmt.Println("Example: -allowed-keys=ABC123,DEF456")
		}
		result := commit.VerifyCommits(clonePath, allowedKeys)
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	}
}
