package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
)

// AnthropicClient implements the client interface for Claude
type AnthropicClient struct {
	model  string
	client anthropic.Client
}

// NewAnthropicClient creates a new Claude client.
// It reads the API key from the ANTHROPIC_API_KEY environment variable.
func NewAnthropicClient(model string) (*AnthropicClient, error) {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicClient{
		model:  model,
		client: anthropic.NewClient(),
	}, nil
}

// Chat sends messages to Claude and returns the response.
func (c *AnthropicClient) Chat(ctx context.Context, messages []Message, tools []Tool) (*Response, error) {
	anthropicMessages := c.convertMessages(messages)
	anthropicTools := c.convertTools(tools)

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: 4096,
		Messages:  anthropicMessages,
	}

	// Extract system message if present
	for _, msg := range messages {
		if msg.Role == RoleSystem {
			params.System = []anthropic.TextBlockParam{
				{
					Type: "text",
					Text: msg.Content,
				},
			}
			break
		}
	}

	if len(anthropicTools) > 0 {
		params.Tools = anthropicTools
	}

	resp, err := c.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return c.parseResponse(resp), nil
}

// convertMessages converts generic Messages to Anthropic's message format.
func (c *AnthropicClient) convertMessages(messages []Message) []anthropic.MessageParam {
	var result []anthropic.MessageParam

	for _, msg := range messages {
		switch msg.Role {
		case RoleSystem:
			// System messages are handled separately in params.System
			continue

		case RoleUser:
			result = append(result, anthropic.NewUserMessage(
				anthropic.NewTextBlock(msg.Content),
			))

		case RoleAssistant:
			if len(msg.ToolCalls) > 0 {
				var blocks []anthropic.ContentBlockParamUnion
				if msg.Content != "" {
					blocks = append(blocks, anthropic.NewTextBlock(msg.Content))
				}
				for _, tc := range msg.ToolCalls {
					blocks = append(blocks, anthropic.ContentBlockParamUnion{
						OfToolUse: &anthropic.ToolUseBlockParam{
							ID:    tc.ID,
							Name:  tc.Name,
							Input: tc.Parameters,
						},
					})
				}
				result = append(result, anthropic.NewAssistantMessage(blocks...))
			} else {
				result = append(result, anthropic.NewAssistantMessage(
					anthropic.NewTextBlock(msg.Content),
				))
			}

		case RoleTool:
			result = append(result, anthropic.NewUserMessage(
				anthropic.NewToolResultBlock(msg.ToolCallID, msg.Content, false),
			))
		}
	}

	return result
}

// convertTools converts generic Tools to Anthropic's tool format.
func (c *AnthropicClient) convertTools(tools []Tool) []anthropic.ToolUnionParam {
	var result []anthropic.ToolUnionParam

	for _, tool := range tools {
		result = append(result, anthropic.ToolUnionParam{
			OfTool: &anthropic.ToolParam{
				Name:        tool.Name,
				Description: anthropic.String(tool.Description),
				InputSchema: anthropic.ToolInputSchemaParam{
					Properties: tool.Parameters,
				},
			},
		})
	}

	return result
}

// parseResponse converts Anthropic's response to the generic Response type.
func (c *AnthropicClient) parseResponse(resp *anthropic.Message) *Response {
	response := &Response{
		Usage: Usage{
			InputTokens:  int(resp.Usage.InputTokens),
			OutputTokens: int(resp.Usage.OutputTokens),
		},
	}

	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			response.Content = block.Text
		case "tool_use":
			var params map[string]interface{}
			if err := json.Unmarshal(block.Input, &params); err != nil {
				params = make(map[string]interface{})
			}
			response.ToolCalls = append(response.ToolCalls, ToolCall{
				ID:         block.ID,
				Name:       block.Name,
				Parameters: params,
			})
		}
	}

	return response
}
