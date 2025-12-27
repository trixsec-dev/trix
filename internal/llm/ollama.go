package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// OllamaClient implements the Client interface for Ollama.
type OllamaClient struct {
	baseURL string
	model   string
	client  *http.Client
}

// NewOllamaClient creates a new Ollama client.
// It reads the base URL from OLLAMA_HOST environment variable or uses localhost:11434.
func NewOllamaClient(baseURL, model string) (*OllamaClient, error) {
	if baseURL == "" {
		baseURL = os.Getenv("OLLAMA_HOST")
	}
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: 5 * time.Minute, // LLMs can be slow
		},
	}, nil
}

// Chat sends messages to Ollama and returns the response.
func (c *OllamaClient) Chat(ctx context.Context, messages []Message, tools []Tool) (*Response, error) {
	ollamaMessages := c.convertMessages(messages)
	ollamaTools := c.convertTools(tools)

	reqBody := ollamaChatRequest{
		Model:    c.model,
		Messages: ollamaMessages,
		Stream:   false,
	}
	if len(ollamaTools) > 0 {
		reqBody.Tools = ollamaTools
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/chat", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResponse(&ollamaResp), nil
}

// Ollama API types

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Tools    []ollamaTool    `json:"tools,omitempty"`
}

type ollamaMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content"`
	ToolCalls  []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type ollamaToolCall struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

type ollamaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type ollamaChatResponse struct {
	Model   string `json:"model"`
	Message struct {
		Role      string           `json:"role"`
		Content   string           `json:"content"`
		ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	} `json:"message"`
	PromptEvalCount int `json:"prompt_eval_count"`
	EvalCount       int `json:"eval_count"`
}

// convertMessages converts generic Messages to Ollama's message format.
func (c *OllamaClient) convertMessages(messages []Message) []ollamaMessage {
	var result []ollamaMessage

	for _, msg := range messages {
		ollamaMsg := ollamaMessage{
			Role:    string(msg.Role),
			Content: msg.Content,
		}

		if msg.Role == RoleTool {
			ollamaMsg.Role = "tool"
			ollamaMsg.ToolCallID = msg.ToolCallID
		}

		if len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				ollamaMsg.ToolCalls = append(ollamaMsg.ToolCalls, ollamaToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: struct {
						Name      string         `json:"name"`
						Arguments map[string]any `json:"arguments"`
					}{
						Name:      tc.Name,
						Arguments: tc.Parameters,
					},
				})
			}
		}

		result = append(result, ollamaMsg)
	}

	return result
}

// convertTools converts generic Tools to Ollama's tool format.
func (c *OllamaClient) convertTools(tools []Tool) []ollamaTool {
	var result []ollamaTool

	for _, tool := range tools {
		result = append(result, ollamaTool{
			Type: "function",
			Function: struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				Parameters  map[string]any `json:"parameters"`
			}{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.Parameters,
			},
		})
	}

	return result
}

// parseResponse converts Ollama's response to the generic Response type.
func (c *OllamaClient) parseResponse(resp *ollamaChatResponse) *Response {
	response := &Response{
		Content: resp.Message.Content,
		Usage: Usage{
			InputTokens:  resp.PromptEvalCount,
			OutputTokens: resp.EvalCount,
		},
	}

	for _, tc := range resp.Message.ToolCalls {
		response.ToolCalls = append(response.ToolCalls, ToolCall{
			ID:         tc.ID,
			Name:       tc.Function.Name,
			Parameters: tc.Function.Arguments,
		})
	}

	return response
}
