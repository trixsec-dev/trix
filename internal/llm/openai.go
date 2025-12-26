package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openai/openai-go"
)

// OpenAIClient implements the Client interface for OpenAI's Chat API.
type OpenAIClient struct {
	model  string
	client openai.Client
}

// NewOpenAIClient creates a new OpenAI client.
// It reads the API key from the OPENAI_API_KEY environment variable.
func NewOpenAIClient(model string) (*OpenAIClient, error) {
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIClient{
		model:  model,
		client: openai.NewClient(),
	}, nil
}

// Chat sends messages to OpenAI and returns the response.
func (c *OpenAIClient) Chat(ctx context.Context, messages []Message, tools []Tool) (*Response, error) {
	openaiMessages := convertMessages(messages)
	openaiTools := convertTools(tools)

	params := openai.ChatCompletionNewParams{
		Messages: openaiMessages,
		Model:    c.model,
	}
	if len(openaiTools) > 0 {
		params.Tools = openaiTools
	}

	resp, err := c.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return parseResponse(resp), nil
}

// convertMessages converts generic Messages to OpenAI's message format.
func convertMessages(messages []Message) []openai.ChatCompletionMessageParamUnion {
	var result []openai.ChatCompletionMessageParamUnion

	for _, msg := range messages {
		switch msg.Role {
		case RoleSystem:
			result = append(result, openai.SystemMessage(msg.Content))

		case RoleUser:
			result = append(result, openai.UserMessage(msg.Content))

		case RoleAssistant:
			if len(msg.ToolCalls) > 0 {
				var toolCalls []openai.ChatCompletionMessageToolCallParam
				for _, tc := range msg.ToolCalls {
					argsJSON, _ := json.Marshal(tc.Parameters)
					toolCalls = append(toolCalls, openai.ChatCompletionMessageToolCallParam{
						ID:   tc.ID,
						Type: "function",
						Function: openai.ChatCompletionMessageToolCallFunctionParam{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					})
				}
				result = append(result, openai.ChatCompletionMessageParamUnion{
					OfAssistant: &openai.ChatCompletionAssistantMessageParam{
						ToolCalls: toolCalls,
					},
				})
			} else {
				result = append(result, openai.AssistantMessage(msg.Content))
			}

		case RoleTool:
			result = append(result, openai.ToolMessage(msg.Content, msg.ToolCallID))
		}
	}

	return result
}

// convertTools converts generic Tools to OpenAI's tool format.
func convertTools(tools []Tool) []openai.ChatCompletionToolParam {
	var result []openai.ChatCompletionToolParam

	for _, tool := range tools {
		result = append(result, openai.ChatCompletionToolParam{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        tool.Name,
				Description: openai.String(tool.Description),
				Parameters:  tool.Parameters,
			},
		})
	}

	return result
}

// parseResponse converts OpenAI's response to the generic Response type.
func parseResponse(resp *openai.ChatCompletion) *Response {
	response := &Response{
		Content: resp.Choices[0].Message.Content,
		Usage: Usage{
			InputTokens:  int(resp.Usage.PromptTokens),
			OutputTokens: int(resp.Usage.CompletionTokens),
		},
	}

	for _, tc := range resp.Choices[0].Message.ToolCalls {
		var params map[string]interface{}
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &params); err != nil {
			params = make(map[string]interface{})
		}

		response.ToolCalls = append(response.ToolCalls, ToolCall{
			ID:         tc.ID,
			Name:       tc.Function.Name,
			Parameters: params,
		})
	}

	return response
}
