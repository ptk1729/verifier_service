package commit

import (
	"os/exec"
	"strings"
)

type CommitCheck struct {
	Commit   string
	Author   string
	KeyID    string
	Verified bool
}

type CommitVerification struct {
	Status         string
	CommitsChecked []CommitCheck
}

// VerifyCommits checks all commits in the repo at repoPath, verifies if each commit is signed by any of the allowedKeys.
// Returns CommitVerification with status PASSED if all are signed by allowed keys, FAILED otherwise.
func VerifyCommits(repoPath string, allowedKeys []string) CommitVerification {
	cmd := exec.Command("git", "-C", repoPath, "log", "--pretty=format:%H|%ae|%G?", "--show-signature")
	out, err := cmd.Output()
	if err != nil {
		return CommitVerification{
			Status: "FAILED",
			CommitsChecked: []CommitCheck{},
		}
	}
	lines := strings.Split(string(out), "\n")
	commits := []CommitCheck{}
	allPassed := true
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		commit := parts[0]
		author := parts[1]
		verifiedFlag := parts[2]
		verified := verifiedFlag == "G" // 'G' means good signature
		keyID := ""
		if verified {
			// Get key ID for this commit
			showCmd := exec.Command("git", "-C", repoPath, "show", "--format=%GK", "-s", commit)
			keyOut, _ := showCmd.Output()
			keyID = strings.TrimSpace(string(keyOut))
			found := false
			for _, allowed := range allowedKeys {
				if keyID == allowed {
					found = true
					break
				}
			}
			verified = found
		}
		if !verified {
			allPassed = false
		}
		commits = append(commits, CommitCheck{
			Commit:   commit,
			Author:   author,
			KeyID:    keyID,
			Verified: verified,
		})
	}
	status := "PASSED"
	if !allPassed {
		status = "FAILED"
	}
	return CommitVerification{
		Status:         status,
		CommitsChecked: commits,
	}
}

