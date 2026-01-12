package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/spf13/cobra"
	"github.com/trixsec-dev/trix/internal/agent"
	"github.com/trixsec-dev/trix/internal/llm"
)

var (
	llmModel    string
	llmProvider string
	ollamaURL   string
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

Providers:
  anthropic  - Requires ANTHROPIC_API_KEY
  openai     - Requires OPENAI_API_KEY
  mistral    - Requires MISTRAL_API_KEY (EU-based)
  ollama     - Local/remote Ollama (set OLLAMA_HOST or use --ollama-url)`,
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
		a := agent.New(client)
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
	askCmd.Flags().StringVar(&llmProvider, "provider", "", "LLM provider: anthropic, openai, ollama (auto-detects if not set)")
	askCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama server URL (default: http://localhost:11434)")
	askCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode for follow-up questions")
}

// createLLMClient creates an LLM client based on --provider flag or auto-detects from env vars
func createLLMClient() (llm.Client, error) {
	provider := llmProvider

	// Auto-detect provider if not specified
	if provider == "" {
		hasAnthropic := os.Getenv("ANTHROPIC_API_KEY") != ""
		hasOpenAI := os.Getenv("OPENAI_API_KEY") != ""
		hasMistral := os.Getenv("MISTRAL_API_KEY") != ""
		hasOllama := os.Getenv("OLLAMA_HOST") != "" || ollamaURL != ""

		// Count how many providers are available
		count := 0
		if hasAnthropic {
			count++
			provider = "anthropic"
		}
		if hasOpenAI {
			count++
			provider = "openai"
		}
		if hasMistral {
			count++
			provider = "mistral"
		}
		if hasOllama {
			count++
			provider = "ollama"
		}

		if count > 1 {
			return nil, fmt.Errorf("multiple providers available. Use --provider to choose (anthropic, openai, mistral, ollama)")
		}
		if count == 0 {
			return nil, fmt.Errorf("no provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, MISTRAL_API_KEY, or OLLAMA_HOST")
		}
	}

	switch provider {
	case "anthropic":
		return llm.NewAnthropicClient(llmModel)
	case "openai":
		return llm.NewOpenAIClient(llmModel)
	case "mistral":
		return llm.NewMistralClient(llmModel)
	case "ollama":
		return llm.NewOllamaClient(ollamaURL, llmModel)
	default:
		return nil, fmt.Errorf("unknown provider: %s (use 'anthropic', 'openai', 'mistral', or 'ollama')", provider)
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
