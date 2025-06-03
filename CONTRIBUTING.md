# Contributing to Truva

We welcome contributions to Truva! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.19 or later
- Kubernetes cluster (for testing)
- Docker (for containerization)

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/Truva.git
   cd Truva
   ```

3. Install dependencies:
   ```bash
   go mod download
   ```

4. Run tests to ensure everything works:
   ```bash
   make test
   ```

## Development Workflow

### Code Style

- Follow Go conventions and use `gofmt`
- Run `go vet` to catch common errors
- Use meaningful variable and function names
- Add comments for exported functions and complex logic

### Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting PR
- Run integration tests:
  ```bash
  go test ./tests/integration/...
  ```

- Run security tests:
  ```bash
  cd security-tests
  make test
  ```

### Submitting Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request

## Commit Message Format

We follow conventional commits:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `test:` for test additions/modifications
- `refactor:` for code refactoring
- `chore:` for maintenance tasks

## Code Review Process

1. All submissions require review
2. Reviewers will check for:
   - Code quality and style
   - Test coverage
   - Security considerations
   - Performance implications

## Security

- Report security vulnerabilities privately
- Follow security best practices
- Never commit secrets or credentials

## Documentation

- Update relevant documentation for new features
- Keep README.md up to date
- Add API documentation for new endpoints

## Questions?

Feel free to open an issue for questions or discussions about contributing.

Thank you for contributing to Truva! 🚀