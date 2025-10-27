# Contributing to Proteus

Thank you for your interest in contributing to Proteus! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and constructive
- Follow best practices and coding standards
- Test your changes thoroughly
- Document new features

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Submit a pull request

## Development Setup
```bash
git clone https://github.com/YOUR_USERNAME/proteus.git
cd proteus
python -m venv venv
venv\Scripts\activate  # Windows
pip install maturin
maturin develop --release
```

## Coding Standards

### Rust
- Follow `rustfmt` formatting
- Pass all `clippy` checks
- No warnings allowed
- Add tests for new features
- No comments in code (prefer self-documenting code)

### Python
- Follow PEP 8
- Use type hints
- Pass `mypy` checks
- Add docstrings for public APIs
- Test coverage required

## Pull Request Process

1. Update documentation
2. Add tests
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review

## Areas for Contribution

- Advanced packer detection
- YARA rule integration
- Performance optimizations
- ML model improvements
- Documentation
- Bug fixes

## Questions?

Open an issue or discussion on GitHub.