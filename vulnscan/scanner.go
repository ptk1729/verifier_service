package vulnscan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strings"
)

type OsvFinding struct {
	ID             string         `json:"id"`
	Package        string         `json:"package"`
	Ecosystem      string         `json:"ecosystem"`
	Summary        string         `json:"summary"`
	Details        string         `json:"details"`
	SeverityObject SeverityObject `json:"severity_object,omitempty"`
	FixedVersion   string         `json:"fixed_version,omitempty"`
}

type SeverityObject struct {
	Level      string `json:"level"`
	Type       string `json:"type"`
	CVSSVector string `json:"cvss_vector"`
	Score      string `json:"score"`
}

type OSVApiVulnerability struct {
	ID       string `json:"id"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type ResultStatus string

const (
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusWarning ResultStatus = "WARNING"
	ResultStatusPassed  ResultStatus = "PASSED"
)

func RunOsvScanner(path string) (ResultStatus, string, []OsvFinding) {
	tool := "osv-scanner"
	status := ResultStatusPassed

	cmd := exec.Command("osv-scanner", "--format", "json", path)
	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			fmt.Println("OSV Scanner execution error:", err)
			fmt.Println("Full output:", outputStr)
			status = ResultStatusFailed
			return status, tool, nil
		}
	}

	jsonStartIndex := strings.Index(outputStr, "{")
	if jsonStartIndex == -1 {
		fmt.Println("Error: Could not find the beginning of the JSON object in the OSV Scanner output.")
		fmt.Println("Full output was:", outputStr)
		status = ResultStatusFailed
		return status, tool, nil
	}
	jsonOutput := outputStr[jsonStartIndex:]

	var osvReport struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string   `json:"id"`
					Summary  string   `json:"summary"`
					Details  string   `json:"details"`
					Aliases  []string `json:"aliases"`
					Affected []struct {
						Ranges []struct {
							Type   string `json:"type"`
							Events []struct {
								Introduced string `json:"introduced"`
								Fixed      string `json:"fixed"`
							} `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(jsonOutput), &osvReport); err != nil {
		fmt.Println("Error unmarshalling OSV Scanner output:", err)
		status = ResultStatusFailed
		return status, tool, nil
	}

	var vulnerabilities []OsvFinding
	for _, result := range osvReport.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				var fixedVersion string
				if len(vuln.Affected) > 0 && len(vuln.Affected[0].Ranges) > 0 {
					for i := len(vuln.Affected[0].Ranges[0].Events) - 1; i >= 0; i-- {
						event := vuln.Affected[0].Ranges[0].Events[i]
						if event.Fixed != "" {
							fixedVersion = event.Fixed
							break
						}
					}
				}
				vulnerabilities = append(vulnerabilities, OsvFinding{
					ID:           vuln.ID,
					Package:      pkg.Package.Name,
					Ecosystem:    pkg.Package.Ecosystem,
					Summary:      vuln.Summary,
					Details:      vuln.Details,
					FixedVersion: fixedVersion,
				})
			}
		}
	}

	if len(vulnerabilities) > 0 {
		status = ResultStatusFailed
	}

	return status, tool, vulnerabilities
}

func EnrichVulnerabilitiesWithSeverity(vulns []OsvFinding) []OsvFinding {
	enrichedVulns := make([]OsvFinding, len(vulns))
	copy(enrichedVulns, vulns)

	for i, v := range enrichedVulns {
		if v.ID == "" {
			continue
		}
		url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", v.ID)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error fetching severity for %s: %v\n", v.ID, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("OSV API returned non-200 status for %s: %s\n", v.ID, resp.Status)
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading API response body for %s: %v\n", v.ID, err)
			continue
		}
		var apiVuln OSVApiVulnerability
		if err := json.Unmarshal(body, &apiVuln); err != nil {
			fmt.Printf("Error unmarshalling API response for %s: %v\n", v.ID, err)
			continue
		}
		humanReadableScore := apiVuln.DatabaseSpecific.Severity
		var CVSS_vector string
		var CVSS_type string
		if len(apiVuln.Severity) > 0 {
			CVSS_type = apiVuln.Severity[0].Type
			CVSS_vector = apiVuln.Severity[0].Score
		}
		if humanReadableScore != "" || CVSS_vector != "" {
			fmt.Printf("Found Severity for %s: Score=%s, Vector=%s\n", v.ID, humanReadableScore, CVSS_vector)
			enrichedVulns[i].SeverityObject = SeverityObject{
				Score:      humanReadableScore,
				Type:       CVSS_type,
				CVSSVector: CVSS_vector,
			}
		}
	}
	return enrichedVulns
}
