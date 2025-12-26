package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/davealtena/trix/internal/chat"
	"github.com/davealtena/trix/internal/llm"
	"github.com/spf13/cobra"
)

var (
	llmModel    string
	llmProvider string
	interactive bool
	renderer    *glamour.TermRenderer
)

var askCmd = &cobra.Command{
	Use:   "ask [question]",
	Short: "Ask questions about your cluster's security",
	Long: `Use AI to investigate security findings in your cluster.

Examples:
  trix ask "What are the critical vulnerabilities in my cluster?"
  trix ask "Why does my nginx deployment have so many CVEs?"
  trix ask "Which pods are most at risk?"
  trix ask "Explain CVE-2024-1234 and how to fix it"

Requires ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		question := strings.Join(args, " ")

		// Initialize markdown renderer
		var err error
		renderer, err = glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(100),
		)
		if err != nil {
			renderer = nil // Fall back to plain text
		}

		// Create LLM client based on provider flag or auto-detect
		client, err := createLLMClient()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Create agent and ask
		a := chat.New(client)
		ctx := context.Background()

		if interactive {
			// Interactive mode with follow-ups
			conv := a.NewConversation()
			scanner := bufio.NewScanner(os.Stdin)

			// First question from args
			fmt.Println("Investigating...")
			response, err := conv.Ask(ctx, question)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println()
			printResponse(response)

			// Follow-up loop
			for {
				fmt.Print("\n> ")
				if !scanner.Scan() {
					break
				}
				input := strings.TrimSpace(scanner.Text())
				if input == "" || input == "exit" || input == "quit" {
					break
				}
				if input == "clear" {
					conv = a.NewConversation()
					fmt.Println("Context cleared.")
					continue
				}

				fmt.Println("Investigating...")
				response, err := conv.Ask(ctx, input)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}
				fmt.Println()
				printResponse(response)
			}
		} else {
			// Single question mode
			fmt.Println("Investigating...")
			response, err := a.Ask(ctx, question)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println()
			printResponse(response)
		}
	},
}

func init() {
	rootCmd.AddCommand(askCmd)
	askCmd.Flags().StringVar(&llmModel, "model", "", "LLM model to use")
	askCmd.Flags().StringVar(&llmProvider, "provider", "", "LLM provider: anthropic, openai (auto-detects if not set)")
	askCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode for follow-up questions")
}

// createLLMClient creates an LLM client based on --provider flag or auto-detects from env vars
func createLLMClient() (llm.Client, error) {
	provider := llmProvider

	// Auto-detect provider if not specified
	if provider == "" {
		if os.Getenv("ANTHROPIC_API_KEY") != "" {
			provider = "anthropic"
		} else if os.Getenv("OPENAI_API_KEY") != "" {
			provider = "openai"
		} else {
			return nil, fmt.Errorf("no API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")
		}
	}

	switch provider {
	case "anthropic":
		return llm.NewAnthropicClient(llmModel)
	case "openai":
		return llm.NewOpenAIClient()
	default:
		return nil, fmt.Errorf("unknown provider: %s (use 'anthropic' or 'openai')", provider)
	}
}

// printResponse renders markdown response to terminal
func printResponse(response string) {
	if renderer != nil {
		out, err := renderer.Render(response)
		if err == nil {
			fmt.Print(out)
			return
		}
	}
	// Fallback to plain text
	fmt.Println(response)
}
