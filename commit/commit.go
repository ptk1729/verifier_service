package commit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ptk1729/verifier_service/types"
)

// GPGKeyStats holds statistics about commit verification
type GPGKeyStats struct {
	TotalCommits    int `json:"total_commits"`
	VerifiedCommits int `json:"verified_commits"`
	UnsignedCommits int `json:"unsigned_commits"`
	BadSignature    int `json:"bad_signature"`
}

// loadGPGKeysFromDataFolder loads all .asc files from the data folder and imports them into GPG
func loadGPGKeysFromDataFolder() ([]string, error) {
	dataFolder := "./data"
	keys := []string{}

	// Check if data folder exists
	if _, err := os.Stat(dataFolder); os.IsNotExist(err) {
		return keys, fmt.Errorf("data folder not found: %s", dataFolder)
	}

	// Find all .asc files in the data folder
	files, err := os.ReadDir(dataFolder)
	if err != nil {
		return keys, fmt.Errorf("failed to read data folder: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".asc") {
			keyPath := filepath.Join(dataFolder, file.Name())

			// Import the GPG key
			importCmd := exec.Command("gpg", "--import", keyPath)
			if err := importCmd.Run(); err != nil {
				fmt.Printf("Warning: Failed to import GPG key %s: %v\n", keyPath, err)
				continue
			}

			// Get the key ID from the imported key
			keyIDCmd := exec.Command("gpg", "--list-keys", "--with-colons")
			keyIDOut, err := keyIDCmd.Output()
			if err != nil {
				fmt.Printf("Warning: Failed to list GPG keys: %v\n", err)
				continue
			}

			// Parse the output to get the latest imported key ID
			lines := strings.Split(string(keyIDOut), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := lines[i]
				if strings.HasPrefix(line, "pub:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 5 {
						keyID := parts[4]
						if keyID != "" {
							keys = append(keys, keyID)
							fmt.Printf("Imported GPG key: %s from %s\n", keyID, file.Name())
							break
						}
					}
				}
			}
		}
	}

	return keys, nil
}

// VerifyCommits checks all commits in the repo at repoPath, verifies if each commit is signed by any of the allowedKeys.
// Returns CommitVerification with status PASSED if all are signed by allowed keys, FAILED otherwise.
func VerifyCommits(repoPath string, allowedKeys []string) types.CommitVerification {
	// Load GPG keys from data folder
	dataKeys, err := loadGPGKeysFromDataFolder()
	if err != nil {
		fmt.Printf("Warning: Failed to load GPG keys from data folder: %v\n", err)
	}

	// Combine allowed keys with data folder keys
	allKeys := append(allowedKeys, dataKeys...)

	if len(allKeys) == 0 {
		fmt.Println("Warning: No GPG keys available for verification")
	}
	// TODO:
	// - make sure the commits happened while the key was valid
	// - make sure multiple keys are supported

	cmd := exec.Command("git", "-C", repoPath, "log", "--pretty=format:%H|%ae|%G?", "--show-signature")
	out, err := cmd.Output()
	if err != nil {
		return types.CommitVerification{
			Status:         types.ResultStatusFailed,
			CommitsChecked: []types.CommitCheck{},
		}
	}

	lines := strings.Split(string(out), "\n")
	commits := []types.CommitCheck{}
	stats := GPGKeyStats{}

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		commit := parts[0]
		author := parts[1]
		verifiedFlag := parts[2]

		stats.TotalCommits++

		var verified bool
		var keyID string

		switch verifiedFlag {
		case "G": // Good signature
			// Get key ID for this commit
			showCmd := exec.Command("git", "-C", repoPath, "show", "--format=%GK", "-s", commit)
			keyOut, _ := showCmd.Output()
			keyID = strings.TrimSpace(string(keyOut))

			// Check if the key is in our allowed keys list
			found := false
			for _, allowed := range allKeys {
				if keyID == allowed {
					found = true
					break
				}
			}

			if found {
				verified = true
				stats.VerifiedCommits++
			} else {
				verified = false
				stats.BadSignature++
			}

		case "B": // Bad signature
			verified = false
			stats.BadSignature++

		case "U": // Good signature with unknown validity
			// Get key ID for this commit
			showCmd := exec.Command("git", "-C", repoPath, "show", "--format=%GK", "-s", commit)
			keyOut, _ := showCmd.Output()
			keyID = strings.TrimSpace(string(keyOut))

			// Check if the key is in our allowed keys list
			found := false
			for _, allowed := range allKeys {
				if keyID == allowed {
					found = true
					break
				}
			}

			if found {
				verified = true
				stats.VerifiedCommits++
			} else {
				verified = false
				stats.BadSignature++
			}

		case "X": // Good signature that has expired
			verified = false
			stats.BadSignature++

		case "Y": // Good signature made by an expired key
			verified = false
			stats.BadSignature++

		case "R": // Good signature with revoked key
			verified = false
			stats.BadSignature++

		case "E": // Cannot check (error occurred)
			verified = false
			stats.BadSignature++

		case "N": // No signature
			verified = false
			stats.UnsignedCommits++

		default:
			verified = false
			stats.UnsignedCommits++
		}

		commits = append(commits, types.CommitCheck{
			Commit:   commit,
			Author:   author,
			KeyID:    keyID,
			Verified: verified,
		})
	}

	// Determine overall status
	allPassed := stats.VerifiedCommits == stats.TotalCommits && stats.TotalCommits > 0
	var allUnverified int = stats.BadSignature + stats.UnsignedCommits
	status := types.ResultStatusPassed
	if !allPassed {
		status = types.ResultStatusFailed
	}

	// Print statistics
	// if allowedKeys is empty then don't print log
	if len(allowedKeys) > 0 {
		fmt.Printf("\n=== Commit Verification Statistics ===\n")
		fmt.Printf("Total commits: %d\n", stats.TotalCommits)
		fmt.Printf("Verified commits: %d\n", stats.VerifiedCommits)
		fmt.Printf("Unsigned commits: %d\n", stats.UnsignedCommits)
		fmt.Printf("Bad signatures: %d\n", stats.BadSignature)
		fmt.Printf("Overall status: %s\n", status)
	}

	return types.CommitVerification{
		Status: status,
		// CommitsChecked:      commits, // TODO: add this back in if needed to see all the commits
		NoVerifiedCommits:   len(commits) - allUnverified,
		NoUnverifiedCommits: allUnverified,
	}
}
