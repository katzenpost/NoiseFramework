# Contributing to NoiseFramework

Thank you for your interest in contributing to NoiseFramework! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, constructive, and professional. We're building a cryptographic library that users trust with their security.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check existing issues to avoid duplicates
2. Verify the bug exists in the latest version
3. Check if it's a security issue (see [SECURITY.md](SECURITY.md))

**Create a bug report with**:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Your environment (Python version, OS, NoiseFramework version)
- Minimal code example
- Error messages and stack traces

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
1. Check if it aligns with the Noise Protocol spec
2. Search existing issues/PRs for similar suggestions
3. Provide clear use case and motivation
4. Consider backward compatibility

### Pull Requests

1. **Fork and clone** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

3. **Set up development environment**:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # or
   source .venv/bin/activate  # Linux/Mac
   
   pip install -e ".[dev]"
   ```

4. **Make your changes** following our guidelines (see below)

5. **Write tests** for your changes:
   ```bash
   pytest tests/
   ```

6. **Format your code**:
   ```bash
   black noiseframework/ tests/
   ```

7. **Run type checking**:
   ```bash
   mypy noiseframework/
   ```

8. **Run linting**:
   ```bash
   ruff check noiseframework/ tests/
   ```

9. **Update documentation**:
   - Add docstrings to new functions/classes
   - Update `README.md` if adding user-facing features
   - Update `docs/CHANGELOG.md` under `[Unreleased]`

10. **Commit your changes**:
    ```bash
    git add .
    git commit -m "feat: add new handshake pattern support"
    ```
    
    Use conventional commit format:
    - `feat:` - New feature
    - `fix:` - Bug fix
    - `docs:` - Documentation changes
    - `test:` - Test additions/changes
    - `refactor:` - Code refactoring
    - `perf:` - Performance improvements
    - `chore:` - Maintenance tasks

11. **Push and create PR**:
    ```bash
    git push origin feature/your-feature-name
    ```
    Then create a Pull Request on GitHub.

## Development Guidelines

### Code Style

- **Python 3.8+** with type hints everywhere
- **PEP 8** compliance via Black formatter
- **Type checking** with mypy (strict mode)
- **Linting** with ruff

### Code Structure

```python
# Good example
def mix_hash(self, data: bytes) -> None:
    """Mix data into the handshake hash.
    
    Args:
        data: The data to mix into the hash.
        
    Raises:
        ValueError: If data is empty.
    """
    if not data:
        raise ValueError("Cannot mix empty data")
    self.h = self.hash_fn(self.h + data)
```

### Testing Requirements

- **All new features MUST have tests**
- **Minimum 90% code coverage** for new code
- **Test structure**: Mirror package structure in `tests/`
- **Test types**:
  - Unit tests for individual functions/classes
  - Integration tests for protocol flows
  - Property-based tests for invariants (using `hypothesis`)

```python
# Example test
def test_handshake_xx_pattern():
    """Test XX pattern handshake between initiator and responder."""
    # Arrange
    initiator = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    initiator.set_as_initiator()
    initiator.generate_static_keypair()
    initiator.initialize()
    
    responder = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
    responder.set_as_responder()
    responder.generate_static_keypair()
    responder.initialize()
    
    # Act
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    # ... continue handshake
    
    # Assert
    assert initiator.handshake_complete
    assert responder.handshake_complete
```

### Documentation Requirements

- **Docstrings**: All public APIs must have comprehensive docstrings
- **Type hints**: All function parameters and return types
- **Examples**: Complex features should include usage examples
- **CHANGELOG**: All changes documented in `docs/CHANGELOG.md`

### Cryptography Guidelines

This is a cryptographic library. Extra care required:

1. **Follow the Noise spec** precisely
2. **Never roll your own crypto** primitives
3. **Use vetted libraries** (`cryptography` package)
4. **Validate inputs** at public API boundaries
5. **Clear error messages** for cryptographic failures
6. **Test vectors** from the spec when available
7. **No magic numbers** - document all constants

### What We Look For

✅ **Good PRs**:
- Solve one problem clearly
- Include comprehensive tests
- Follow existing code style
- Update documentation
- Have descriptive commit messages

❌ **Avoid**:
- Multiple unrelated changes in one PR
- Breaking existing APIs without discussion
- Missing tests
- Unformatted code
- Security vulnerabilities

## Project Structure

```
noiseframework/
├── crypto/          # Cryptographic primitives
│   ├── dh.py       # Diffie-Hellman
│   ├── cipher.py   # AEAD ciphers
│   └── hash.py     # Hash functions
├── noise/          # Noise protocol implementation
│   ├── pattern.py  # Pattern parsing
│   ├── state.py    # Cipher and symmetric state
│   └── handshake.py # Handshake state machine
├── transport/      # Post-handshake transport
│   └── transport.py
└── cli/            # Command-line interface
    └── main.py
```

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: See [SECURITY.md](SECURITY.md)
- **Chat**: (If you set up Discord/Slack, add here)

## Recognition

Contributors will be:
- Listed in `docs/CHANGELOG.md` for their contributions
- Acknowledged in release notes
- Given credit in any security advisories they help resolve

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make NoiseFramework better and more secure! 🔒
