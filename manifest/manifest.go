package manifest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ptk1729/verifier_service/types"
	"gopkg.in/yaml.v3"
)

// ScanManifests scans the repository for Dockerfiles and Kubernetes manifests
func ScanManifests(repoPath string) types.ManifestScanResult {
	result := types.ManifestScanResult{
		Status:              string(types.ResultStatusPassed),
		Tool:                "manifest-scanner",
		Dockerfiles:         []types.DockerfileInfo{},
		KubernetesManifests: []types.KubernetesManifestInfo{},
		TotalFiles:          0,
		FilesWithIssues:     0,
	}

	dockerfiles := findDockerfiles(repoPath)
	for _, dockerfile := range dockerfiles {
		dockerfileInfo := scanDockerfile(dockerfile)
		result.Dockerfiles = append(result.Dockerfiles, dockerfileInfo)
		result.TotalFiles++
		if dockerfileInfo.HasIssues {
			result.FilesWithIssues++
		}
	}

	k8sManifests := findKubernetesManifests(repoPath)
	for _, manifest := range k8sManifests {
		manifestInfo := scanKubernetesManifest(manifest)
		// Only include valid Kubernetes manifests in the results
		if manifestInfo.Kind != "" && !manifestInfo.HasIssues {
			result.KubernetesManifests = append(result.KubernetesManifests, manifestInfo)
			result.TotalFiles++
		}
	}

	if result.FilesWithIssues > 0 {
		result.Status = string(types.ResultStatusWarning)
	}

	return result
}

// findDockerfiles finds all Dockerfiles in the repository
func findDockerfiles(repoPath string) []string {
	var dockerfiles []string

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Check for Dockerfile (case-insensitive)
		filename := strings.ToLower(info.Name())
		if filename == "dockerfile" || strings.HasPrefix(filename, "dockerfile.") || strings.HasSuffix(filename, ".dockerfile") {
			dockerfiles = append(dockerfiles, path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
	}

	return dockerfiles
}

// findKubernetesManifests finds all Kubernetes manifests in the repository
func findKubernetesManifests(repoPath string) []string {
	var manifests []string

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Check for YAML files that might be Kubernetes manifests
		if strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") ||
			strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			manifests = append(manifests, path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
	}

	return manifests
}

// scanDockerfile scans a Dockerfile for ports and environment variables
func scanDockerfile(filePath string) types.DockerfileInfo {
	info := types.DockerfileInfo{
		Path:            filePath,
		ExposedPorts:    []types.PortInfo{},
		EnvironmentVars: []types.EnvVarInfo{},
		HasIssues:       false,
		Issues:          []string{},
	}

	file, err := os.Open(filePath)
	if err != nil {
		info.HasIssues = true
		info.Issues = append(info.Issues, fmt.Sprintf("Failed to open file: %v", err))
		return info
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	exposePattern := regexp.MustCompile(`(?i)^\s*EXPOSE\s+(.+)$`)
	envPattern := regexp.MustCompile(`(?i)^\s*ENV\s+([^=]+)=(.*)$`)
	envPattern2 := regexp.MustCompile(`(?i)^\s*ENV\s+([^=]+)\s+(.*)$`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		if matches := exposePattern.FindStringSubmatch(line); matches != nil {
			ports := parseExposedPorts(matches[1])
			info.ExposedPorts = append(info.ExposedPorts, ports...)
		}

		if matches := envPattern.FindStringSubmatch(line); matches != nil {
			info.EnvironmentVars = append(info.EnvironmentVars, types.EnvVarInfo{
				Name:  strings.TrimSpace(matches[1]),
				Value: strings.TrimSpace(matches[2]),
				Type:  "env",
			})
		}

		if matches := envPattern2.FindStringSubmatch(line); matches != nil {
			info.EnvironmentVars = append(info.EnvironmentVars, types.EnvVarInfo{
				Name:  strings.TrimSpace(matches[1]),
				Value: strings.TrimSpace(matches[2]),
				Type:  "env",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		info.HasIssues = true
		info.Issues = append(info.Issues, fmt.Sprintf("Error reading file: %v", err))
	}

	return info
}

// scanKubernetesManifest scans a Kubernetes manifest for ports and environment variables
func scanKubernetesManifest(filePath string) types.KubernetesManifestInfo {
	info := types.KubernetesManifestInfo{
		Path:            filePath,
		Kind:            "",
		Name:            "",
		ExposedPorts:    []types.PortInfo{},
		EnvironmentVars: []types.EnvVarInfo{},
		HasIssues:       false,
		Issues:          []string{},
	}

	file, err := os.Open(filePath)
	if err != nil {
		info.HasIssues = true
		info.Issues = append(info.Issues, fmt.Sprintf("Failed to open file: %v", err))
		return info
	}
	defer file.Close()

	var manifest map[string]interface{}
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&manifest); err != nil {
		info.HasIssues = true
		info.Issues = append(info.Issues, fmt.Sprintf("Failed to parse YAML: %v", err))
		return info
	}

	// Extract basic metadata
	if kind, ok := manifest["kind"].(string); ok {
		info.Kind = kind
	}
	if metadata, ok := manifest["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			info.Name = name
		}
	}

	if !isKubernetesManifest(manifest) {
		info.HasIssues = true
		info.Issues = append(info.Issues, "Not a valid Kubernetes manifest")
		return info
	}

	switch info.Kind {
	case "Service":
		info.ExposedPorts = extractServicePorts(manifest)
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		info.ExposedPorts = extractContainerPorts(manifest)
		info.EnvironmentVars = extractContainerEnvVars(manifest)
	case "Pod":
		info.ExposedPorts = extractContainerPorts(manifest)
		info.EnvironmentVars = extractContainerEnvVars(manifest)
	}

	return info
}

// parseExposedPorts parses the EXPOSE directive ports
func parseExposedPorts(portsStr string) []types.PortInfo {
	var ports []types.PortInfo

	// Split by spaces and commas
	portStrings := regexp.MustCompile(`[,\s]+`).Split(portsStr, -1)

	for _, portStr := range portStrings {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		parts := strings.Split(portStr, "/")
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue // Skip invalid ports
		}

		protocol := "tcp" // Default protocol
		if len(parts) > 1 {
			protocol = strings.ToLower(parts[1])
		}

		ports = append(ports, types.PortInfo{
			Port:     port,
			Protocol: protocol,
			Type:     "exposed",
		})
	}

	return ports
}

// isKubernetesManifest checks if the parsed YAML is a Kubernetes manifest
func isKubernetesManifest(manifest map[string]interface{}) bool {
	// Check for required Kubernetes fields
	if _, ok := manifest["apiVersion"]; !ok {
		return false
	}
	if _, ok := manifest["kind"]; !ok {
		return false
	}
	if _, ok := manifest["metadata"]; !ok {
		return false
	}

	// Check for common Kubernetes API versions
	apiVersion, ok := manifest["apiVersion"].(string)
	if !ok {
		return false
	}

	// Common Kubernetes API versions
	validAPIVersions := []string{
		"v1", "apps/v1", "apps/v1beta1", "apps/v1beta2",
		"batch/v1", "batch/v1beta1", "batch/v1beta2",
		"extensions/v1beta1", "networking.k8s.io/v1",
		"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1beta1",
		"storage.k8s.io/v1", "storage.k8s.io/v1beta1",
		"policy/v1beta1", "policy/v1",
		"autoscaling/v1", "autoscaling/v2", "autoscaling/v2beta1", "autoscaling/v2beta2",
		"certificates.k8s.io/v1", "certificates.k8s.io/v1beta1",
		"admissionregistration.k8s.io/v1", "admissionregistration.k8s.io/v1beta1",
		"apiextensions.k8s.io/v1", "apiextensions.k8s.io/v1beta1",
		"apiregistration.k8s.io/v1", "apiregistration.k8s.io/v1beta1",
		"coordination.k8s.io/v1", "coordination.k8s.io/v1beta1",
		"discovery.k8s.io/v1", "discovery.k8s.io/v1beta1",
		"events.k8s.io/v1", "events.k8s.io/v1beta1",
		"flowcontrol.apiserver.k8s.io/v1beta1", "flowcontrol.apiserver.k8s.io/v1beta2",
		"flowcontrol.apiserver.k8s.io/v1beta3",
		"node.k8s.io/v1", "node.k8s.io/v1alpha1", "node.k8s.io/v1beta1",
		"scheduling.k8s.io/v1", "scheduling.k8s.io/v1beta1",
		"snapshot.storage.k8s.io/v1", "snapshot.storage.k8s.io/v1beta1",
		"metrics.k8s.io/v1beta1",
		"custom.metrics.k8s.io/v1beta1", "custom.metrics.k8s.io/v1beta2",
		"external.metrics.k8s.io/v1beta1",
	}

	for _, validVersion := range validAPIVersions {
		if strings.HasPrefix(apiVersion, validVersion) {
			return true
		}
	}

	return false
}

// extractServicePorts extracts ports from a Service manifest
func extractServicePorts(manifest map[string]interface{}) []types.PortInfo {
	var ports []types.PortInfo

	if spec, ok := manifest["spec"].(map[string]interface{}); ok {
		if portsList, ok := spec["ports"].([]interface{}); ok {
			for _, portInterface := range portsList {
				if portMap, ok := portInterface.(map[string]interface{}); ok {
					port := types.PortInfo{Type: "service"}

					if portNum, ok := portMap["port"].(int); ok {
						port.Port = portNum
					}

					if protocol, ok := portMap["protocol"].(string); ok {
						port.Protocol = strings.ToLower(protocol)
					} else {
						port.Protocol = "tcp" // Default
					}

					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

// extractContainerPorts extracts ports from container specifications
func extractContainerPorts(manifest map[string]interface{}) []types.PortInfo {
	var ports []types.PortInfo

	// Handle different workload types
	containers := extractContainers(manifest)

	for _, container := range containers {
		if containerPorts, ok := container["ports"].([]interface{}); ok {
			for _, portInterface := range containerPorts {
				if portMap, ok := portInterface.(map[string]interface{}); ok {
					port := types.PortInfo{Type: "container"}

					if containerPort, ok := portMap["containerPort"].(int); ok {
						port.Port = containerPort
					}

					if protocol, ok := portMap["protocol"].(string); ok {
						port.Protocol = strings.ToLower(protocol)
					} else {
						port.Protocol = "tcp" // Default
					}

					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

// extractContainerEnvVars extracts environment variables from container specifications
func extractContainerEnvVars(manifest map[string]interface{}) []types.EnvVarInfo {
	var envVars []types.EnvVarInfo

	containers := extractContainers(manifest)

	for _, container := range containers {
		if envList, ok := container["env"].([]interface{}); ok {
			for _, envInterface := range envList {
				if envMap, ok := envInterface.(map[string]interface{}); ok {
					envVar := types.EnvVarInfo{Type: "env"}

					if name, ok := envMap["name"].(string); ok {
						envVar.Name = name
					}

					if value, ok := envMap["value"].(string); ok {
						envVar.Value = value
					}

					envVars = append(envVars, envVar)
				}
			}
		}

		if envFromList, ok := container["envFrom"].([]interface{}); ok {
			for _, envFromInterface := range envFromList {
				if envFromMap, ok := envFromInterface.(map[string]interface{}); ok {
					envVar := types.EnvVarInfo{}

					if configMapRef, ok := envFromMap["configMapRef"].(map[string]interface{}); ok {
						if name, ok := configMapRef["name"].(string); ok {
							envVar.Name = name
							envVar.Type = "configMap"
							envVars = append(envVars, envVar)
						}
					}

					if secretRef, ok := envFromMap["secretRef"].(map[string]interface{}); ok {
						if name, ok := secretRef["name"].(string); ok {
							envVar.Name = name
							envVar.Type = "secret"
							envVars = append(envVars, envVar)
						}
					}
				}
			}
		}
	}

	return envVars
}

// extractContainers extracts container specifications from different workload types
func extractContainers(manifest map[string]interface{}) []map[string]interface{} {
	var containers []map[string]interface{}

	if spec, ok := manifest["spec"].(map[string]interface{}); ok {
		if containerList, ok := spec["containers"].([]interface{}); ok {
			for _, containerInterface := range containerList {
				if container, ok := containerInterface.(map[string]interface{}); ok {
					containers = append(containers, container)
				}
			}
		}

		if template, ok := spec["template"].(map[string]interface{}); ok {
			if podSpec, ok := template["spec"].(map[string]interface{}); ok {
				if containerList, ok := podSpec["containers"].([]interface{}); ok {
					for _, containerInterface := range containerList {
						if container, ok := containerInterface.(map[string]interface{}); ok {
							containers = append(containers, container)
						}
					}
				}
			}
		}

		if jobTemplate, ok := spec["jobTemplate"].(map[string]interface{}); ok {
			if jobSpec, ok := jobTemplate["spec"].(map[string]interface{}); ok {
				if template, ok := jobSpec["template"].(map[string]interface{}); ok {
					if podSpec, ok := template["spec"].(map[string]interface{}); ok {
						if containerList, ok := podSpec["containers"].([]interface{}); ok {
							for _, containerInterface := range containerList {
								if container, ok := containerInterface.(map[string]interface{}); ok {
									containers = append(containers, container)
								}
							}
						}
					}
				}
			}
		}
	}

	return containers
}
