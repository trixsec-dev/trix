<div align="center">
  <h1>trix</h1>
  <p><strong>Kubernetes Security Scanner with AI-Powered Triage</strong></p>

  <p>
    Query vulnerabilities, compliance issues, and security posture from your cluster.<br>
    Use AI to investigate findings and get actionable remediation advice.
  </p>

  <p>
    <a href="https://go.dev/"><img src="https://img.shields.io/github/go-mod/go-version/davealtena/trix" alt="Go Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/davealtena/trix" alt="License"></a>
    <a href="https://goreportcard.com/report/github.com/davealtena/trix"><img src="https://goreportcard.com/badge/github.com/davealtena/trix" alt="Go Report Card"></a>
    <a href="https://github.com/davealtena/trix/releases"><img src="https://img.shields.io/github/v/release/davealtena/trix?include_prereleases" alt="Release"></a>
  </p>

  <p>
    <a href="#features"><strong>Features</strong></a> |
    <a href="#installation"><strong>Installation</strong></a> |
    <a href="#usage"><strong>Usage</strong></a> |
    <a href="#ai-powered-investigation"><strong>AI Investigation</strong></a> |
    <a href="#roadmap"><strong>Roadmap</strong></a>
  </p>
</div>

---

## Features

- **Query Security Findings** - Browse vulnerabilities, compliance issues, RBAC problems, and exposed secrets
- **AI-Powered Investigation** - Ask questions in natural language and get actionable remediation advice
- **SBOM Search** - Find specific packages across all container images (e.g., log4j)
- **NetworkPolicy Analysis** - Identify pods without network protection
- **Interactive Mode** - Have follow-up conversations about your security posture
- **BYOK (Bring Your Own Key)** - Your data stays between you and your LLM provider
- **Multiple Output Formats** - Human-readable tables or JSON for automation

## Supported Tools

| Tool | Status | Description |
|------|--------|-------------|
| Trivy Operator | ✅ Supported | Vulnerabilities, compliance, RBAC, secrets, SBOM |
| Kubescape | 🔜 Planned | NSA/CISA hardening checks |
| Kyverno | 🔜 Planned | Policy violations |
| Falco | 🔜 Planned | Runtime security events |

## How it Works

trix is a local CLI tool that queries security data from your Kubernetes cluster via kubeconfig. [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) runs in-cluster and scans your workloads - trix reads those results and makes them actionable.

### What trix finds

| Finding Type | Description |
|--------------|-------------|
| **Vulnerabilities** | CVEs in container images with CVSS scores |
| **Compliance** | Misconfigurations and policy violations |
| **RBAC Issues** | Overly permissive roles and bindings |
| **Exposed Secrets** | Secrets found in container images |
| **NetworkPolicy Gaps** | Pods without network protection |
| **Software Inventory** | SBOM data for all images |

## Installation

### Prerequisites

- Access to a Kubernetes cluster
- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed in your cluster

<details>
<summary>Install Trivy Operator (if not already installed)</summary>

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace
```

</details>

### Install trix

**From source:**

```bash
git clone https://github.com/davealtena/trix.git
cd trix
go build -o trix .
sudo mv trix /usr/local/bin/
```

**Container image:**

```bash
docker run --rm -v ~/.kube:/home/nonroot/.kube:ro ghcr.io/davealtena/trix:latest status
```

**Verify installation:**

```bash
trix version
trix status  # Check Trivy Operator connection
```

## Usage

### Query Security Findings

```bash
# View all findings across namespaces
trix query findings -A

# Summary with severity breakdown
trix query summary -A

# Filter by namespace
trix query findings -n production

# JSON output for automation
trix query findings -A -o json
```

### Check NetworkPolicy Coverage

```bash
trix query network -A
```

### Search Software Inventory (SBOM)

```bash
# List all images and components
trix query sbom -A

# Search for specific packages (e.g., log4j)
trix query sbom -A --package log4j
```

### Trigger Rescans

```bash
# Rescan vulnerabilities in a namespace
trix scan vulns -n default

# Rescan everything (with confirmation skip)
trix scan all -A -y
```

### Example Output

```
$ trix query summary -A

Security Findings Summary
=========================

Total Findings: 884

By Severity:
  CRITICAL:  12
  HIGH:      45
  MEDIUM:    234
  LOW:       593

By Type:
  vulnerability: 763
  compliance:    47
  rbac:          11

Top Affected Resources:
  kube-system/etcd-control-plane - 112 findings
  kube-system/kube-apiserver - 89 findings
```

## AI-Powered Investigation

Use natural language to investigate your cluster's security posture. trix uses AI to query findings, analyze RBAC, and provide actionable remediation steps.

**Bring Your Own Key (BYOK):** You provide your own LLM API key. Your data stays between you and your LLM provider.

### Setup

```bash
# Option 1: Anthropic Claude
export ANTHROPIC_API_KEY=your-key-here

# Option 2: OpenAI GPT
export OPENAI_API_KEY=your-key-here

# Option 3: Ollama (local, experimental)
export OLLAMA_HOST=http://localhost:11434
```

trix auto-detects which provider to use based on available environment variables.

### Ask Questions

```bash
# Single question
trix ask "What are the top 5 security risks in my cluster?"

# Interactive mode for follow-up questions
trix ask "What critical vulnerabilities do I have?" -i
```

### Interactive Mode

```
$ trix ask "What critical vulnerabilities are in my cluster?" -i
Investigating...
  → trix query summary -A
  → trix query findings --severity=CRITICAL
  [tokens: 2477 in, 357 out | total: 5548 in, 507 out]

## Critical Security Issues Summary
Your cluster has 20 critical vulnerabilities across 8 workloads...

> How do I fix CVE-2024-45337?
Investigating...
  → trix finding detail CVE-2024-45337
  [tokens: 3200 in, 450 out | total: 8748 in, 957 out]

## How to Patch CVE-2024-45337
Update the golang.org/x/crypto package to version 0.31.0 or later...
```

**Commands in interactive mode:**
- Type your question and press Enter
- `clear` - Reset conversation context
- `exit` or `quit` - Exit

### Supported LLM Providers

| Provider | Status | Environment Variable |
|----------|--------|---------------------|
| Anthropic (Claude) | Supported | `ANTHROPIC_API_KEY` |
| OpenAI (GPT-4) | Supported | `OPENAI_API_KEY` |
| Ollama (local) | Experimental | `OLLAMA_HOST` |

Use `--provider` to explicitly select a provider:

```bash
trix ask "..." --provider anthropic
trix ask "..." --provider openai
trix ask "..." --provider ollama --model llama3.1:8b
```

#### Ollama (Experimental)

Ollama support allows running trix with local LLMs for air-gapped environments. Note that local models have limited multi-step tool calling capability compared to hosted models.

```bash
# Start Ollama
ollama serve

# Pull a model
ollama pull llama3.1:8b

# Use with trix
export OLLAMA_HOST=http://localhost:11434
trix ask "What vulnerabilities are in my cluster?" --provider ollama

# Or specify model explicitly
trix ask "..." --provider ollama --model qwen2.5:14b --ollama-url http://localhost:11434
```

Recommended models for tool calling: `llama3.1:8b`, `qwen2.5:14b`, `mistral`

## Roadmap

- **Server Mode** - REST API for in-cluster deployment
- **Helm Chart** - Easy deployment and configuration
- **More Security Tools** - Kubescape, Kyverno, Falco integrations
- **Webhook Integrations** - Slack, Teams, PagerDuty notifications

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

- [Open an issue](https://github.com/davealtena/trix/issues) for bugs or feature requests
- [Start a discussion](https://github.com/davealtena/trix/discussions) for questions or ideas

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for more information.
