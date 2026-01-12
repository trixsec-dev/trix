package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/trixsec-dev/trix/internal/llm"
	"github.com/trixsec-dev/trix/internal/tools/exposure"
	"github.com/trixsec-dev/trix/internal/tools/kubectl"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Executor runs a tools and returns the result
type Executor func(ctx context.Context, params map[string]interface{}) (string, error)

// Registry holds all available tools
type Registry struct {
	tools     map[string]llm.Tool
	executors map[string]Executor
}

// NewRegistry creates a registry with default tools
func NewRegistry() *Registry {
	r := &Registry{
		tools:     make(map[string]llm.Tool),
		executors: make(map[string]Executor),
	}
	r.RegisterDefaults()
	return r
}

// Tools returns all tool definitions for the LLM
func (r *Registry) Tools() []llm.Tool {
	var tools []llm.Tool
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	return tools
}

// Execute runs a tool by name
func (r *Registry) Execute(ctx context.Context, name string, params map[string]interface{}) (string, error) {
	executor, ok := r.executors[name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	return executor(ctx, params)
}

func (r *Registry) RegisterDefaults() {
	// kubectl_list - compact listing of resources (token-efficient)
	r.register(llm.Tool{
		Name:        "kubectl_list",
		Description: "List Kubernetes resources in compact table format (name, namespace, status). Use this FIRST to find resources, then use kubectl_get for details of ONE specific resource.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"resource":       map[string]string{"type": "string", "description": "Resource type (pods, deployments, services, clusterrolebindings, etc.)"},
				"namespace":      map[string]string{"type": "string", "description": "Namespace (optional, omit for current namespace)"},
				"all_namespaces": map[string]string{"type": "boolean", "description": "List across all namespaces"},
				"selector":       map[string]string{"type": "string", "description": "Label selector to filter (optional, e.g., 'app=nginx')"},
			},
			"required": []string{"resource"},
		},
	}, r.kubectlList)

	// kubectl_get - get FULL details for ONE specific resource
	r.register(llm.Tool{
		Name:        "kubectl_get",
		Description: "Get FULL YAML details for ONE specific resource. Use kubectl_list first to find resource names, then use this for details. WARNING: Do NOT use without a specific name - use kubectl_list for listings.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"resource":  map[string]string{"type": "string", "description": "Resource type (pod, deployment, service, etc.)"},
				"name":      map[string]string{"type": "string", "description": "Resource name (REQUIRED - use kubectl_list to find names first)"},
				"namespace": map[string]string{"type": "string", "description": "Namespace (required for namespaced resources)"},
			},
			"required": []string{"resource", "name"},
		},
	}, r.kubectlGet)

	//kubectl_logs - get pod logs
	r.register(llm.Tool{
		Name:        "kubectl_logs",
		Description: "Get logs from a pod. Use this to investigate errors or runtime behavior.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pod":       map[string]string{"type": "string", "description": "Pod name"},
				"namespace": map[string]string{"type": "string", "description": "Namespace"},
				"tail":      map[string]string{"type": "integer", "description": "Number of lines (default 50)"},
			},
			"required": []string{"pod", "namespace"},
		},
	}, r.kubectlLogs)

	// trix_findings - query security findings (compact list)
	r.register(llm.Tool{
		Name:        "trix_findings",
		Description: "List security findings in compact format. Returns ID, severity, type, resource, and title. Use trix_finding_detail to get full details for a specific finding.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]string{"type": "string", "description": "Namespace to query (optional, omit for all)"},
				"type":      map[string]string{"type": "string", "description": "Finding type: vulnerability, compliance, rbac, secret, infra (optional)"},
				"severity":  map[string]string{"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW (optional, recommended)"},
				"limit":     map[string]string{"type": "integer", "description": "Max findings to return (default 20)"},
			},
		},
	}, r.trixFindings)

	// trix_finding_detail - get full details for a specific finding
	r.register(llm.Tool{
		Name:        "trix_finding_detail",
		Description: "Get full details for a specific finding by ID. Use this after trix_findings to get description, remediation steps, and raw data.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]string{"type": "string", "description": "Finding ID from trix_findings output"},
			},
			"required": []string{"id"},
		},
	}, r.trixFindingDetail)

	// trix_summary - get aggregated summary
	r.register(llm.Tool{
		Name:        "trix_summary",
		Description: "Get aggregated security summary with counts by severity and type. Use this FIRST to understand the overall security posture before drilling into specific findings.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]string{"type": "string", "description": "Namespace to query (optional, omit for all)"},
			},
		},
	}, r.trixSummary)

	// trix_sbom_summary - SBOM overview (token-efficient)
	r.register(llm.Tool{
		Name:        "trix_sbom_summary",
		Description: "Get SBOM summary: total images, component counts by type, top 10 most common packages. Use this FIRST before searching for specific packages.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}, r.trixSbomSummary)

	// trix_sbom_search - search for specific package
	r.register(llm.Tool{
		Name:        "trix_sbom_search",
		Description: "Search for a specific package across all images. Returns compact list: image, namespace, package name, version. Use this to find if a package (e.g., log4j) exists in your cluster.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"package": map[string]string{"type": "string", "description": "Package name to search for (case-insensitive, partial match)"},
			},
			"required": []string{"package"},
		},
	}, r.trixSbomSearch)

	// trix_sbom_image - full SBOM for one image
	r.register(llm.Tool{
		Name:        "trix_sbom_image",
		Description: "Get full SBOM (all components) for a specific image. Use after trix_sbom_search to see what else is in a particular image. Can be large (100-500 components).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"image": map[string]string{"type": "string", "description": "Image name (partial match, e.g., 'nginx' or 'backend-api')"},
			},
			"required": []string{"image"},
		},
	}, r.trixSbomImage)

	// check_exposure - analyze workload exposure for CVE prioritization
	r.register(llm.Tool{
		Name:        "check_exposure",
		Description: "Check if a workload is exposed externally (via Service, Ingress, Gateway API). Use this to prioritize CVE remediation - externally exposed workloads are higher priority. Returns exposure level and details.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":      map[string]string{"type": "string", "description": "Workload name (e.g., 'nginx-deployment')"},
				"namespace": map[string]string{"type": "string", "description": "Namespace"},
				"kind":      map[string]string{"type": "string", "description": "Workload kind: Deployment, DaemonSet, StatefulSet, Pod (default: Deployment)"},
			},
			"required": []string{"name", "namespace"},
		},
	}, r.checkExposure)
}

func (r *Registry) register(tool llm.Tool, executor Executor) {
	r.tools[tool.Name] = tool
	r.executors[tool.Name] = executor
}

// Tool implementations

func (r *Registry) kubectlList(ctx context.Context, params map[string]interface{}) (string, error) {
	resource, _ := params["resource"].(string)
	namespace, _ := params["namespace"].(string)
	allNamespaces, _ := params["all_namespaces"].(bool)
	selector, _ := params["selector"].(string)

	args := []string{"get", resource}
	if allNamespaces {
		args = append(args, "-A")
	} else if namespace != "" {
		args = append(args, "-n", namespace)
	}
	if selector != "" {
		args = append(args, "-l", selector)
	}
	// Use wide output for more info but still compact
	args = append(args, "-o", "wide")

	output, err := r.runCommand(ctx, "kubectl", args...)
	if err != nil {
		return output, err
	}

	// Count lines to give context
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > 1 {
		output = fmt.Sprintf("Found %d %s:\n\n%s", len(lines)-1, resource, output)
	}

	return output, nil
}

func (r *Registry) kubectlGet(ctx context.Context, params map[string]interface{}) (string, error) {
	resource, _ := params["resource"].(string)
	name, _ := params["name"].(string)
	namespace, _ := params["namespace"].(string)

	// Require a specific name to prevent massive outputs
	if name == "" {
		return "", fmt.Errorf("name is required - use kubectl_list to find resource names first")
	}

	args := []string{"get", resource, name}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, "-o", "yaml")

	return r.runCommand(ctx, "kubectl", args...)
}

func (r *Registry) kubectlLogs(ctx context.Context, params map[string]interface{}) (string, error) {
	pod, _ := params["pod"].(string)
	namespace, _ := params["namespace"].(string)
	tail := 50
	if t, ok := params["tail"].(float64); ok {
		tail = int(t)
	}
	args := []string{"logs", pod, "-n", namespace, "--tail", fmt.Sprintf("%d", tail)}
	return r.runCommand(ctx, "kubectl", args...)
}

func (r *Registry) trixFindings(ctx context.Context, params map[string]interface{}) (string, error) {
	namespace, _ := params["namespace"].(string)
	findingType, _ := params["type"].(string)
	severity, _ := params["severity"].(string)
	limit := 20
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	// Get path to current executable
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	args := []string{"query", "findings", "-o", "json"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	output, err := r.runCommand(ctx, exe, args...)
	if err != nil {
		return "", err
	}

	// Format as compact list
	return r.formatFindingsCompact(output, findingType, severity, limit)
}

func (r *Registry) trixFindingDetail(ctx context.Context, params map[string]interface{}) (string, error) {
	id, _ := params["id"].(string)
	if id == "" {
		return "", fmt.Errorf("id parameter is required")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	args := []string{"query", "findings", "-o", "json", "-A"}
	output, err := r.runCommand(ctx, exe, args...)
	if err != nil {
		return "", err
	}

	// Find the specific finding
	var findings []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &findings); err != nil {
		return "", fmt.Errorf("failed to parse findings: %w", err)
	}

	for _, f := range findings {
		if fid, ok := f["id"].(string); ok && strings.EqualFold(fid, id) {
			// Return full details without rawData to save tokens
			delete(f, "rawData")
			result, _ := json.MarshalIndent(f, "", "  ")
			return string(result), nil
		}
	}

	return "", fmt.Errorf("finding not found: %s", id)
}

func (r *Registry) trixSummary(ctx context.Context, params map[string]interface{}) (string, error) {
	namespace, _ := params["namespace"].(string)

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	args := []string{"query", "summary"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	return r.runCommand(ctx, exe, args...)
}

func (r *Registry) formatFindingsCompact(jsonOutput, findingType, severity string, limit int) (string, error) {
	var findings []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOutput), &findings); err != nil {
		return jsonOutput, nil // Return as-is if not JSON
	}

	var lines []string
	lines = append(lines, "ID | Severity | Type | Resource | Title")
	lines = append(lines, "---|----------|------|----------|------")

	count := 0
	for _, f := range findings {
		// Check type filter
		if findingType != "" {
			if t, ok := f["type"].(string); !ok || !strings.EqualFold(t, findingType) {
				continue
			}
		}
		// Check severity filter
		if severity != "" {
			if s, ok := f["severity"].(string); !ok || !strings.EqualFold(s, severity) {
				continue
			}
		}

		// Extract fields
		id, _ := f["id"].(string)
		sev, _ := f["severity"].(string)
		typ, _ := f["type"].(string)
		ns, _ := f["namespace"].(string)
		name, _ := f["resourceName"].(string)
		title, _ := f["title"].(string)

		// Truncate long titles
		if len(title) > 60 {
			title = title[:57] + "..."
		}

		resource := name
		if ns != "" {
			resource = ns + "/" + name
		}

		lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s", id, sev, typ, resource, title))

		count++
		if count >= limit {
			lines = append(lines, fmt.Sprintf("... (showing %d of %d findings, use limit parameter for more)", limit, len(findings)))
			break
		}
	}

	if count == 0 {
		return "No findings match the specified filters.", nil
	}

	return strings.Join(lines, "\n"), nil
}

func (r *Registry) runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w\n%s", err, output)
	}
	return string(output), nil
}

// SBOM tool implementations

func (r *Registry) trixSbomSummary(ctx context.Context, params map[string]interface{}) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	// Get SBOM data as JSON
	args := []string{"query", "sbom", "-A", "-o", "json"}
	output, err := r.runCommand(ctx, exe, args...)
	if err != nil {
		return "", err
	}

	// Parse and summarize
	var sboms []struct {
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		Image      string `json:"image"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}

	if err := json.Unmarshal([]byte(output), &sboms); err != nil {
		return "", fmt.Errorf("failed to parse SBOM data: %w", err)
	}

	// Aggregate stats
	totalImages := len(sboms)
	totalComponents := 0
	typeCount := make(map[string]int)
	packageCount := make(map[string]int)

	for _, sbom := range sboms {
		totalComponents += len(sbom.Components)
		for _, comp := range sbom.Components {
			typeCount[comp.Type]++
			packageCount[comp.Name]++
		}
	}

	// Build summary
	var lines []string
	lines = append(lines, fmt.Sprintln("SBOM Summary"))
	lines = append(lines, fmt.Sprintln("============"))
	lines = append(lines, fmt.Sprintf("Total images scanned: %d", totalImages))
	lines = append(lines, fmt.Sprintf("Total components: %d", totalComponents))
	lines = append(lines, "")
	lines = append(lines, "Components by type:")
	for t, count := range typeCount {
		lines = append(lines, fmt.Sprintf("  %s: %d", t, count))
	}

	// Top 10 most common packages
	lines = append(lines, "")
	lines = append(lines, "Top 10 most common packages:")
	type pkgCount struct {
		name  string
		count int
	}
	var sorted []pkgCount
	for name, count := range packageCount {
		sorted = append(sorted, pkgCount{name, count})
	}
	// Simple sort (bubble sort for small data)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i := 0; i < 10 && i < len(sorted); i++ {
		lines = append(lines, fmt.Sprintf("  %d. %s (in %d images)", i+1, sorted[i].name, sorted[i].count))
	}

	return strings.Join(lines, "\n"), nil
}

func (r *Registry) trixSbomSearch(ctx context.Context, params map[string]interface{}) (string, error) {
	pkg, _ := params["package"].(string)
	if pkg == "" {
		return "", fmt.Errorf("package parameter is required")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	// Use the existing --package filter
	args := []string{"query", "sbom", "-A", "--package", pkg}
	output, err := r.runCommand(ctx, exe, args...)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(output) == "" {
		return fmt.Sprintf("No packages matching '%s' found in any image.", pkg), nil
	}

	// Add header
	result := fmt.Sprintf("Packages matching '%s':\n", pkg)
	result += "Image | Package | Version | Type\n"
	result += "------|---------|---------|-----\n"
	result += output

	return result, nil
}

func (r *Registry) trixSbomImage(ctx context.Context, params map[string]interface{}) (string, error) {
	image, _ := params["image"].(string)
	if image == "" {
		return "", fmt.Errorf("image parameter is required")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to find executable: %w", err)
	}

	// Get all SBOM data
	args := []string{"query", "sbom", "-A", "-o", "json"}
	output, err := r.runCommand(ctx, exe, args...)
	if err != nil {
		return "", err
	}

	var sboms []struct {
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		Image      string `json:"image"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}

	if err := json.Unmarshal([]byte(output), &sboms); err != nil {
		return "", fmt.Errorf("failed to parse SBOM data: %w", err)
	}

	// Find matching image
	imageLower := strings.ToLower(image)
	for _, sbom := range sboms {
		if strings.Contains(strings.ToLower(sbom.Image), imageLower) ||
			strings.Contains(strings.ToLower(sbom.Name), imageLower) {
			// Build component list
			var lines []string
			lines = append(lines, fmt.Sprintf("SBOM for: %s", sbom.Image))
			lines = append(lines, fmt.Sprintf("Namespace: %s", sbom.Namespace))
			lines = append(lines, fmt.Sprintf("Total components: %d", len(sbom.Components)))
			lines = append(lines, "")
			lines = append(lines, "Package | Version | Type")
			lines = append(lines, "--------|---------|-----")

			for _, comp := range sbom.Components {
				lines = append(lines, fmt.Sprintf("%s | %s | %s", comp.Name, comp.Version, comp.Type))
			}

			return strings.Join(lines, "\n"), nil
		}
	}

	return fmt.Sprintf("No image matching '%s' found. Available images:\n%s",
		image, r.listImageNames(sboms)), nil
}

func (r *Registry) listImageNames(sboms []struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Image      string `json:"image"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"components"`
}) string {
	var names []string
	for _, sbom := range sboms {
		names = append(names, fmt.Sprintf("  - %s (%s)", sbom.Image, sbom.Namespace))
	}
	if len(names) > 10 {
		names = names[:10]
		names = append(names, "  ... and more")
	}
	return strings.Join(names, "\n")
}

// checkExposure analyzes workload exposure for CVE prioritization
func (r *Registry) checkExposure(ctx context.Context, params map[string]interface{}) (string, error) {
	name, _ := params["name"].(string)
	namespace, _ := params["namespace"].(string)
	kind, _ := params["kind"].(string)

	if name == "" || namespace == "" {
		return "", fmt.Errorf("name and namespace are required")
	}
	if kind == "" {
		kind = "Deployment"
	}

	// Create k8s client
	client, err := kubectl.NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Get workload labels based on kind
	labels, err := r.getWorkloadLabels(ctx, client, kind, name, namespace)
	if err != nil {
		return "", fmt.Errorf("failed to get workload: %w", err)
	}

	// Create workload struct
	workload := exposure.Workload{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}

	// Create analyzer with all checkers
	analyzer := exposure.NewAnalyzer(
		exposure.NewServiceChecker(client.Clientset()),
		exposure.NewIngressChecker(client.Clientset()),
		exposure.NewGatewayChecker(client.Clientset(), client.DynamicClient()),
	)

	// Run analysis
	result, err := analyzer.Analyze(ctx, workload)
	if err != nil {
		return "", fmt.Errorf("exposure analysis failed: %w", err)
	}

	// Return compact output for token efficiency
	return result.CompactString(), nil
}

// getWorkloadLabels fetches the pod template labels for a workload
func (r *Registry) getWorkloadLabels(ctx context.Context, client *kubectl.Client, kind, name, namespace string) (map[string]string, error) {
	clientset := client.Clientset()

	switch kind {
	case "Deployment":
		deploy, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return deploy.Spec.Selector.MatchLabels, nil

	case "DaemonSet":
		ds, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return ds.Spec.Selector.MatchLabels, nil

	case "StatefulSet":
		sts, err := clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return sts.Spec.Selector.MatchLabels, nil

	case "Pod":
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return pod.Labels, nil

	default:
		return nil, fmt.Errorf("unsupported workload kind: %s (use Deployment, DaemonSet, StatefulSet, or Pod)", kind)
	}
}
