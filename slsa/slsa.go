package slsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
)

type ResultStatus string

const (
	ResultStatusPassed  ResultStatus = "PASSED"
	ResultStatusFailed  ResultStatus = "FAILED"
	ResultStatusSkipped ResultStatus = "SKIPPED"
	ResultStatusWarning ResultStatus = "WARNING"
)

type Material struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

type RequirementCheck struct {
	Name   string       `json:"name"`
	Status ResultStatus `json:"status"`
}

type SlsaCheckResult struct {
	Status            ResultStatus       `json:"status"`
	BinaryPath        string             `json:"binary_path"`
	ProvenancePath    string             `json:"provenance_path"`
	SourceURI         string             `json:"source_uri"`
	SlsaLevel         string             `json:"slsa_level"`
	MissingProvenance bool               `json:"missing_provenance"`
	ErrorMessage      string             `json:"error_message,omitempty"`
	BuilderID         string             `json:"builder_id,omitempty"`
	Materials         []Material         `json:"materials,omitempty"`
	Requirements      []RequirementCheck `json:"verified_requirements,omitempty"`
}

// RunSlsaCheck verifies the given binary against its provenance using the SLSA verifier API.
// It returns a populated SlsaCheckResult that callers can act upon.
func RunSlsaCheck(ctx context.Context, binaryPath, provenancePath, sourceURI string) SlsaCheckResult {
	var res SlsaCheckResult
	res.BinaryPath, res.ProvenancePath, res.SourceURI = binaryPath, provenancePath, sourceURI

	if binaryPath == "" || provenancePath == "" || sourceURI == "" {
		res.Status = ResultStatusSkipped
		res.ErrorMessage = "skipping slsa verification as binaryPath, provenancePath, or sourceURI is empty"
		return res
	}

	// Gather requirement results for more granular reporting.
	addReq := func(name string, ok bool) {
		status := ResultStatusFailed
		if ok {
			status = ResultStatusPassed
		}
		res.Requirements = append(res.Requirements, RequirementCheck{Name: name, Status: status})
	}

	// 1. Confirm binary exists ------------------------------------------------
	if err := fileMustExist(binaryPath); err != nil {
		res.Status = ResultStatusFailed
		res.ErrorMessage = fmt.Sprintf("binary not found: %v", err)
		addReq("binary_exists", false)
		return res
	}
	addReq("binary_exists", true)

	// 2. Confirm provenance file exists --------------------------------------
	if err := fileMustExist(provenancePath); err != nil {
		res.Status = ResultStatusFailed
		res.MissingProvenance = true
		res.ErrorMessage = fmt.Sprintf("provenance not found: %v", err)
		addReq("provenance_exists", false)
		return res
	}
	addReq("provenance_exists", true)

	// 3. Compute SHA‑256 digest ---------------------------------------------
	digest, err := sha256File(binaryPath)
	if err != nil {
		res.Status = ResultStatusFailed
		res.ErrorMessage = fmt.Sprintf("failed to compute digest: %v", err)
		addReq("digest_computed", false)
		return res
	}
	addReq("digest_computed", true)

	// 4. Load provenance bytes ----------------------------------------------
	provenanceBytes, err := os.ReadFile(provenancePath)
	if err != nil {
		res.Status = ResultStatusFailed
		res.ErrorMessage = fmt.Sprintf("failed to read provenance: %v", err)
		addReq("provenance_read", false)
		return res
	}
	addReq("provenance_read", true)

	// 5. Prepare verifier options -------------------------------------------
	provOpts := &options.ProvenanceOpts{
		ExpectedSourceURI: sourceURI,
		ExpectedDigest:    digest,
	}
	builderOpts := &options.BuilderOpts{}

	// 6. Verify --------------------------------------------------------------
	_, builderID, err := verifiers.VerifyArtifact(
		ctx,
		provenanceBytes,
		digest,
		provOpts,
		builderOpts,
	)
	if err != nil {
		res.Status = ResultStatusFailed
		res.ErrorMessage = err.Error()
		addReq("signature_and_policy", false)
		return res
	}
	addReq("signature_and_policy", true)

	// 7. Extract additional details -----------------------------------------
	// Materials list --------------------------------------------------------
	res.Materials = extractMaterials(provenanceBytes)

	// Builder ID ------------------------------------------------------------
	if builderID != nil {
		if id := builderID.String(); id != "" {
			res.BuilderID = id
		}
	}

	// Source URI requirement outcome (redundant but explicit) --------------
	addReq("source_uri_match", true)

	// 8. Success -------------------------------------------------------------
	res.Status = ResultStatusPassed
	res.SlsaLevel = "Unknown" // TODO: derive when API provides level info or via heuristic.
	return res
}

// extractMaterials parses the DSSE envelope and returns a simplified list of materials.
// Any parsing errors are ignored; we return what we can.
func extractMaterials(dsseBytes []byte) []Material {
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(dsseBytes, &env); err != nil {
		return nil
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil
	}
	var stmt struct {
		Predicate struct {
			Materials []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"materials"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil
	}
	var out []Material
	for _, m := range stmt.Predicate.Materials {
		dig := ""
		if d, ok := m.Digest["sha256"]; ok {
			dig = d
		} else {
			for _, v := range m.Digest {
				dig = v
				break
			}
		}
		out = append(out, Material{URI: m.URI, Digest: dig})
	}
	return out
}

// CheckSlsaLevel returns the level stored in the result or a fallback.
func CheckSlsaLevel(r SlsaCheckResult) string {
	if r.SlsaLevel != "" {
		return r.SlsaLevel
	}
	return "Unknown"
}

func fileMustExist(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
