package agent

import (
	"context"
	"fmt"

	"github.com/trixsec-dev/trix/internal/llm"
	"github.com/trixsec-dev/trix/internal/tools"
)

const systemPrompt = `You are a Kubernetes security investigator. You help users understand security findings in their clusters.

When investigating SECURITY FINDINGS:
1. Start with trix_summary to understand the overall security posture
2. Use trix_findings with severity filter to get a compact list of issues
3. Use trix_finding_detail ONLY when you need full details about a specific finding
4. Use kubectl_list to find resources, then kubectl_get for ONE specific resource
5. Use kubectl_logs only if investigating runtime issues

When investigating SBOM (software inventory):
1. Start with trix_sbom_summary for overview (total images, component types, top packages)
2. Use trix_sbom_search to find specific packages (e.g., "is log4j in my cluster?")
3. Use trix_sbom_image ONLY when you need full SBOM for ONE specific image

When investigating Kubernetes resources:
1. Use kubectl_list to get compact table of resources (names, namespaces, status)
2. Use kubectl_get ONLY for ONE specific resource by name (returns full YAML)
3. NEVER use kubectl_get without a specific name - it will error

When PRIORITIZING vulnerabilities:
1. Use check_exposure to see if a workload is externally reachable
2. ALWAYS report CRITICAL CVEs, but add exposure context:
   - External: "CRITICAL - internet-facing, patch immediately"
   - NodePort: "CRITICAL - may be external depending on network"
   - ClusterIP: "CRITICAL - internal only, lower urgency"
   - None: "CRITICAL - not network accessible, lowest urgency"
3. check_exposure on Deployment covers its ReplicaSets/Pods - don't check both

Tool usage guidelines (TOKEN EFFICIENCY IS CRITICAL):
- trix_summary, trix_sbom_summary, kubectl_list, check_exposure → COMPACT, use first
- trix_findings (with filters) → COMPACT table, efficient for overviews
- trix_finding_detail, kubectl_get, trix_sbom_image → FULL details, use for ONE item only
- NEVER fetch full data when a summary or filtered list will answer the question

CRITICAL - RBAC findings:
- ClusterRoles named cluster-admin, admin, edit, view, system:* are BUILT-IN to Kubernetes - not actionable.
- BEFORE listing RBAC as a risk: run kubectl_list clusterrolebindings and CHECK the subjects
- System subjects (system:*, kube-system/*, kubernetes-admin) are EXPECTED and SAFE
- If only system subjects are bound: DO NOT list RBAC as a risk at all. Skip it entirely.
- Only list RBAC as a risk if you find NON-system users/groups/serviceaccounts bound to powerful roles.

Be concise and focus on ACTIONABLE insights. Don't just say "review" - actually check and tell the user what needs to change.
NEVER end with questions like "Would you like me to..." or "Do you want me to..." - just provide the complete answer.
NEVER use emojis in your responses.
When asked for "top N risks/issues", only list actual problems. Don't pad with "no issues found" items.
EFFICIENCY: Aim to answer in 5-7 tool calls max. Don't fetch the same data twice. Be decisive.`

// Token limits
const (
	maxToolOutputBytes = 30000 // 30KB per tool output (~7500 tokens)
	warnTokenThreshold = 50000 // Warn when input exceeds this
)

// Conversation holds state for multi-return conversations
type Conversation struct {
	agent             *Agent
	messages          []llm.Message
	TotalInputTokens  int
	TotalOutputTokens int
}

// NewConversation start a new converstation
func (a *Agent) NewConversation() *Conversation {
	return &Conversation{
		agent: a,
		messages: []llm.Message{
			{Role: llm.RoleSystem, Content: systemPrompt},
		},
	}
}

// Ask adds a question and returns
func (c *Conversation) Ask(ctx context.Context, question string) (string, error) {
	c.messages = append(c.messages, llm.Message{Role: llm.RoleUser, Content: question})

	for i := 0; i < 10; i++ {
		response, err := c.agent.client.Chat(ctx, c.messages, c.agent.registry.Tools())
		if err != nil {
			return "", fmt.Errorf("LLM error: %w", err)
		}

		// Track token usage
		c.TotalInputTokens += response.Usage.InputTokens
		c.TotalOutputTokens += response.Usage.OutputTokens

		if len(response.ToolCalls) == 0 {
			// Add final assistant response to history
			c.messages = append(c.messages, llm.Message{
				Role:    llm.RoleAssistant,
				Content: response.Content,
			})
			// Show token usage
			fmt.Printf("  [tokens: %d in, %d out | total: %d in, %d out]\n",
				response.Usage.InputTokens, response.Usage.OutputTokens,
				c.TotalInputTokens, c.TotalOutputTokens)
			// Warn if context is getting large
			if response.Usage.InputTokens > warnTokenThreshold {
				fmt.Printf("  [warning: context is large, consider using 'clear' to reset]\n")
			}
			return response.Content, nil
		}

		c.messages = append(c.messages, llm.Message{
			Role:      llm.RoleAssistant,
			Content:   response.Content,
			ToolCalls: response.ToolCalls,
		})
		for _, tc := range response.ToolCalls {
			paramInfo := formatToolParams(tc.Name, tc.Parameters)
			fmt.Printf("  → %s\n", paramInfo)

			result, err := c.agent.registry.Execute(ctx, tc.Name, tc.Parameters)
			if err != nil {
				result = fmt.Sprintf("Error: %v", err)
			}

			if len(result) > maxToolOutputBytes {
				result = result[:maxToolOutputBytes] + "\n... (truncated)"
			}

			c.messages = append(c.messages, llm.Message{
				Role:       llm.RoleTool,
				Content:    result,
				ToolCallID: tc.ID,
			})
		}
	}
	return "", fmt.Errorf("agent loop exceeded maximum iterations")
}

// Agent handles the conversation loop with the LLM
type Agent struct {
	client   llm.Client
	registry *tools.Registry
}

// New creates a new agent
func New(client llm.Client) *Agent {
	return &Agent{
		client:   client,
		registry: tools.NewRegistry(),
	}
}

// Ask processes a user question and returns the response
func (a *Agent) Ask(ctx context.Context, question string) (string, error) {
	messages := []llm.Message{
		{Role: llm.RoleSystem, Content: systemPrompt},
		{Role: llm.RoleUser, Content: question},
	}

	var totalIn, totalOut int

	// Agent loop - keep going until we get a text response
	for i := 0; i < 10; i++ { // Max 10 iterations to prevent infinite loops
		response, err := a.client.Chat(ctx, messages, a.registry.Tools())
		if err != nil {
			return "", fmt.Errorf("LLM error: %w", err)
		}

		totalIn += response.Usage.InputTokens
		totalOut += response.Usage.OutputTokens

		// If no tool calls, we're done
		if len(response.ToolCalls) == 0 {
			fmt.Printf("  [tokens: %d in, %d out]\n", totalIn, totalOut)
			return response.Content, nil
		}

		// Add assistant message with tool calls
		messages = append(messages, llm.Message{
			Role:      llm.RoleAssistant,
			Content:   response.Content,
			ToolCalls: response.ToolCalls,
		})

		// Execute each tool and add results
		for _, tc := range response.ToolCalls {
			// Show tool name with key parameters
			paramInfo := formatToolParams(tc.Name, tc.Parameters)
			fmt.Printf("  → %s\n", paramInfo)

			result, err := a.registry.Execute(ctx, tc.Name, tc.Parameters)
			if err != nil {
				result = fmt.Sprintf("Error: %v", err)
			}

			// Truncate very long results
			if len(result) > maxToolOutputBytes {
				result = result[:maxToolOutputBytes] + "\n... (truncated)"
			}

			messages = append(messages, llm.Message{
				Role:       llm.RoleTool,
				Content:    result,
				ToolCallID: tc.ID,
			})
		}
	}
	return "", fmt.Errorf("agent loop exceeded maximum iterations")
}

// formatToolParams creates a readable description of a tool call
func formatToolParams(name string, params map[string]interface{}) string {
	switch name {
	case "kubectl_list":
		resource, _ := params["resource"].(string)
		ns, _ := params["namespace"].(string)
		allNs, _ := params["all_namespaces"].(bool)
		selector, _ := params["selector"].(string)
		cmd := fmt.Sprintf("kubectl get %s", resource)
		if allNs {
			cmd += " -A"
		} else if ns != "" {
			cmd += " -n " + ns
		}
		if selector != "" {
			cmd += " -l " + selector
		}
		return cmd
	case "kubectl_get":
		resource, _ := params["resource"].(string)
		ns, _ := params["namespace"].(string)
		rname, _ := params["name"].(string)
		if rname != "" && ns != "" {
			return fmt.Sprintf("kubectl get %s/%s -n %s -o yaml", resource, rname, ns)
		} else if rname != "" {
			return fmt.Sprintf("kubectl get %s/%s -o yaml", resource, rname)
		}
		return fmt.Sprintf("kubectl get %s", resource)
	case "kubectl_logs":
		pod, _ := params["pod"].(string)
		ns, _ := params["namespace"].(string)
		return fmt.Sprintf("kubectl logs %s -n %s", pod, ns)
	case "trix_findings":
		sev, _ := params["severity"].(string)
		typ, _ := params["type"].(string)
		if sev != "" && typ != "" {
			return fmt.Sprintf("trix query findings --severity=%s --type=%s", sev, typ)
		} else if sev != "" {
			return fmt.Sprintf("trix query findings --severity=%s", sev)
		} else if typ != "" {
			return fmt.Sprintf("trix query findings --type=%s", typ)
		}
		return "trix query findings -A"
	case "trix_summary":
		return "trix query summary -A"
	case "trix_finding_detail":
		id, _ := params["id"].(string)
		return fmt.Sprintf("trix finding detail %s", id)
	case "trix_sbom_summary":
		return "trix sbom summary"
	case "trix_sbom_search":
		pkg, _ := params["package"].(string)
		return fmt.Sprintf("trix sbom search --package=%s", pkg)
	case "trix_sbom_image":
		img, _ := params["image"].(string)
		return fmt.Sprintf("trix sbom image %s", img)
	case "check_exposure":
		name, _ := params["name"].(string)
		ns, _ := params["namespace"].(string)
		kind, _ := params["kind"].(string)
		if kind == "" {
			kind = "Deployment"
		}
		return fmt.Sprintf("check exposure %s/%s (%s)", ns, name, kind)
	default:
		return fmt.Sprintf("Calling %s...", name)
	}
}
