package utils

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
)

// RandomUUID generates a random UUID string
func RandomUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// SaveJSON saves data to a JSON file
func SaveJSON(data interface{}, filename string) {
	file, _ := json.MarshalIndent(data, "", "  ")
	ioutil.WriteFile(filename, file, 0644)
}

// Run executes a command and returns the output as string
func Run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// GetLatestCommit gets the latest commit hash from the git repository
func GetLatestCommit(path string) string {
	out := Run("git", "-C", path, "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

// GetCommitAuthor gets the author email for a specific commit
func GetCommitAuthor(path, commit string) string {
	out := Run("git", "-C", path, "show", "-s", "--format=%ae", commit)
	return strings.TrimSpace(out)
}
