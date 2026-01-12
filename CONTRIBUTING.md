# Contributing to trix

Thanks for your interest in contributing to trix!

## Development Setup

### Prerequisites

- Go 1.24+
- [pre-commit](https://pre-commit.com/)

### Install pre-commit hooks

```bash
# Install pre-commit (macOS)
brew install pre-commit

# Install pre-commit (pip)
pip install pre-commit

# Install the hooks
pre-commit install

# Run hooks on all files (first time)
pre-commit run --all-files
```

## Code Style

We use standard Go tooling to maintain code quality:

- **go fmt** - Code formatting (enforced)
- **go vet** - Static analysis
- **golangci-lint** - Comprehensive linting

The pre-commit hooks will run these automatically before each commit.

### Manual checks

```bash
# Format code
go fmt ./...

# Run vet
go vet ./...

# Run linter
golangci-lint run
```

## Testing

```bash
# Run all tests
go test ./...

# Run tests with race detector
go test -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your feature (`git checkout -b feature/amazing-feature`)
3. **Make your changes** and ensure tests pass
4. **Commit** with a clear message
5. **Push** to your fork
6. **Open a Pull Request**

### PR Guidelines

- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new functionality
- Ensure CI passes before requesting review

## Reporting Issues

- Use [GitHub Issues](https://github.com/trixsec-dev/trix/issues) for bugs and feature requests
- Include steps to reproduce for bugs
- Check existing issues before creating a new one

## Questions?

Start a [Discussion](https://github.com/trixsec-dev/trix/discussions) for questions or ideas.
