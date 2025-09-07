package main

import (
	"context"
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
	"github.com/ptk1729/verifier_service/slsa"
	"github.com/ptk1729/verifier_service/utils"
	"github.com/ptk1729/verifier_service/vulnscan"
)

func main() {
	now := time.Now().Format("20060102150405")
	var (
		lintFlag        = flag.Bool("lint", false, "Run only linting check")
		formatFlag      = flag.Bool("format", false, "Run only formatting check")
		vulnFlag        = flag.Bool("vuln", false, "Run only vulnerability check")
		envFlag         = flag.Bool("env", false, "Run only environment variables check")
		reviewsFlag     = flag.Bool("reviews", false, "Run only reviews check")
		customFlag      = flag.Bool("custom", false, "Run only custom checks")
		commitFlag      = flag.Bool("commit", false, "Run only commit verification check")
		slsaFlag        = flag.Bool("slsa", false, "Run only SLSA (Supply chain Levels for Software Artifacts) check")
		printReportFlag = flag.Bool("print-report", false, "Print the full report to console")
		requiredReviews = flag.Int("required-reviews", 2, "Number of required reviews")
		allowedKeys     = flag.String("allowed-keys", "", "Comma-separated list of allowed GPG key IDs for commit verification")
		binaryPath      = flag.String("binary-path", "", "Path to the binary file for SLSA verification")
		provenancePath  = flag.String("provenance-path", "", "Path to the provenance file (.intoto.jsonl) for SLSA verification")
		sourceURI       = flag.String("source-uri", "", "Source URI for SLSA verification (e.g., git+https://github.com/user/repo)")
		projectNameCLI  = flag.String("project-name", "Default Project Name", "Project name for the report")
		reportPath      = flag.String("report-path", "/tmp/report_"+now+".json", "Path to save the report (with filename included)")
	)

	flag.Parse()

	individualCheck := *lintFlag || *formatFlag || *vulnFlag || *envFlag || *reviewsFlag || *customFlag || *commitFlag || *slsaFlag

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: go run main.go [flags] <repo_url>")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go https://github.com/user/repo")
		fmt.Println("  go run main.go -lint https://github.com/user/repo")
		fmt.Println("  go run main.go -vuln https://github.com/user/repo")
		fmt.Println("  go run main.go -slsa -binary-path=/path/to/binary -provenance-path=/path/to/provenance.intoto.jsonl -source-uri=git+https://github.com/user/repo https://github.com/user/repo")
		fmt.Println("  go run main.go -commit -allowed-keys=ABC123,DEF456 https://github.com/user/repo")
		fmt.Println("  go run main.go -print-report https://github.com/user/repo")
		fmt.Println("  go run main.go -sign -private-key=private_key.bin https://github.com/user/repo")
		fmt.Println("  go run main.go -verify -public-key=public_key.bin report_file.json")
		fmt.Println("  go run main.go -report-path=/path/to/save/report https://github.com/user/repo")
		os.Exit(1)
	}

	repoURL := args[0]
	projectName := *projectNameCLI
	if projectName == "" {
		projectName = "Default Project Name"
	}
	clonePath := "./repo_clone"
	verifierVersion := "1.0.0"

	var allowedKeysList []string
	if *allowedKeys != "" {
		allowedKeysList = strings.Split(*allowedKeys, ",")
		for i, key := range allowedKeysList {
			allowedKeysList[i] = strings.TrimSpace(key)
		}
	}

	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		os.RemoveAll(clonePath)
	}
	utils.Run("git", "clone", repoURL, clonePath)

	if individualCheck {
		runIndividualCheck(clonePath, *lintFlag, *formatFlag, *vulnFlag, *envFlag, *reviewsFlag, *customFlag, *commitFlag, *slsaFlag, *requiredReviews, allowedKeysList, *binaryPath, *provenancePath, *sourceURI)
	} else {
		verificationReport, err := report.GenerateReport(
			projectName,
			repoURL,
			clonePath,
			verifierVersion,
			*requiredReviews,
			allowedKeysList,
			*binaryPath,
			*provenancePath,
			*sourceURI,
		)
		if err != nil {
			fmt.Printf("Error generating report: %v\n", err)
			os.Exit(1)
		}

		reportName := fmt.Sprintf("%s", *reportPath)
		utils.SaveJSON(verificationReport, reportName)

		fmt.Printf("Done. Report saved to %s\n", reportName)
		if *printReportFlag {
			reportJSON, _ := json.MarshalIndent(verificationReport, "", "  ")
			fmt.Println(string(reportJSON))
		}
	}
}

func runIndividualCheck(clonePath string, lint, format, vuln, env, reviewsFlag, custom, commitFlag, slsaFlag bool, requiredReviews int, allowedKeys []string, binaryPath, provenancePath, sourceURI string) {
	if lint {
		fmt.Println("=== LINTING CHECK ===")
		result := linting.RunLint(clonePath)
		fmt.Println(result)
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

	if slsaFlag {
		fmt.Println("=== SLSA CHECK ===")

		// Validate required parameters
		if binaryPath == "" {
			fmt.Println("Error: -binary-path is required for SLSA verification")
			fmt.Println("Example: -binary-path=/path/to/binary")
			return
		}
		if provenancePath == "" {
			fmt.Println("Error: -provenance-path is required for SLSA verification")
			fmt.Println("Example: -provenance-path=/path/to/provenance.intoto.jsonl")
			return
		}
		if sourceURI == "" {
			fmt.Println("Error: -source-uri is required for SLSA verification")
			fmt.Println("Example: -source-uri=git+https://github.com/user/repo")
			return
		}

		fmt.Println("binaryPath: ", binaryPath)
		fmt.Println("provenancePath: ", provenancePath)
		fmt.Println("sourceURI: ", sourceURI)
		result := slsa.RunSlsaCheck(context.Background(), binaryPath, provenancePath, sourceURI)

		fmt.Println("Level:", slsa.CheckSlsaLevel(result))

		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
		fmt.Printf("SLSA Level: %s\n", slsa.CheckSlsaLevel(result))

		if result.MissingProvenance {
			fmt.Println("\nRecommendations:")
			fmt.Println("- Consider implementing SLSA provenance generation in your CI/CD pipeline")
			fmt.Println("- Use tools like slsa-framework/slsa-github-generator for GitHub Actions")
			fmt.Println("- Add .intoto.jsonl or provenance.json files to your repository")
		}
	}
}
