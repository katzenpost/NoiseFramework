# PyPI Release Process

This document outlines the complete process for releasing NoiseFramework to PyPI.

## Prerequisites

### Required Tools

Ensure you have the following tools installed:

```powershell
# Install/upgrade build tools
python -m pip install --upgrade pip
python -m pip install --upgrade build twine
```

### Version Update Checklist

Before releasing, ensure version numbers are updated in:

- [ ] `pyproject.toml` - Main version specification
- [ ] `noiseframework/__init__.py` - `__version__` variable
- [ ] `noiseframework/cli/main.py` - CLI version string
- [ ] `docs/CHANGELOG.md` - Add new version section with date

### Pre-Release Validation

Run the full test suite to ensure everything works:

```powershell
# Run all tests
python -m pytest tests/ -v

# Check test coverage
python -m pytest tests/ --cov=noiseframework --cov-report=term-missing

# Verify CLI works
python -m noiseframework.cli.main --version
```

## Build Process

### 1. Clean Old Build Artifacts

Remove any previous build files to ensure a clean build:

```powershell
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path noiseframework.egg-info) { Remove-Item -Recurse -Force noiseframework.egg-info }
```

### 2. Build the Package

Build both source distribution (`.tar.gz`) and wheel (`.whl`):

```powershell
python -m build
```

This creates:
- `dist/noiseframework-{VERSION}.tar.gz` - Source distribution
- `dist/noiseframework-{VERSION}-py3-none-any.whl` - Universal wheel

### 3. Verify Build Contents

Check that the built package contains all necessary files:

```powershell
# List built files
Get-ChildItem dist

# Inspect wheel contents
python -m zipfile -l dist/noiseframework-*.whl

# Verify package metadata
python -m twine check dist/*
```

## Upload to PyPI

### Test PyPI (Optional but Recommended)

Upload to TestPyPI first to verify everything works:

```powershell
# Upload to TestPyPI
python -m twine upload --repository testpypi dist/noiseframework-{VERSION}*

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ noiseframework
```

### Production PyPI Upload

Upload the package to the official PyPI:

```powershell
python -m twine upload dist/noiseframework-{VERSION}* -u __token__ -p PYPI_API_KEY_HERE
```

> **Note:** Replace `PYPI_API_KEY_HERE` with your actual PyPI API token.
> **Note:** Replace {VERSION} with the actual version number (e.g. 1.2.6).

Alternatively, you can store the token in a `.env` file (ensure it's in `.gitignore`):

```powershell
# Read token from .env file
$token = Get-Content .env | Select-String "pypi-" | ForEach-Object { $_.Line.Split("-p ")[-1] }
python -m twine upload dist/noiseframework-{VERSION}* -u __token__ -p $token
```

## Post-Release Steps

### 1. Verify PyPI Package

Check that the package appears correctly on PyPI:

- Visit: https://pypi.org/project/noiseframework/
- Verify version number, description, and metadata
- Check that README renders correctly

### 2. Test Installation

Test installing from PyPI in a clean environment:

```powershell
# Create fresh virtual environment
python -m venv test_env
test_env\Scripts\Activate.ps1

# Install from PyPI
pip install noiseframework

# Verify installation
python -c "import noiseframework; print(noiseframework.__version__)"
noiseframework --version

# Cleanup
deactivate
Remove-Item -Recurse -Force test_env
```

### 3. Create Git Tag

Tag the release in Git:

```powershell
# Create annotated tag
git tag -a v{VERSION} -m "Release version {VERSION}"

# Push tag to GitHub
git push origin v{VERSION}
```

### 4. Create GitHub Release

1. Go to: https://github.com/juliuspleunes4/NoiseFramework/releases/new
2. Select the tag you just created
3. Title: `v{VERSION}`
4. Copy release notes from `docs/CHANGELOG.md`
5. Publish release

### 5. Update Documentation

If necessary, update any documentation that references the version number:

- README.md badges
- Installation instructions
- Migration guides

## Troubleshooting

### Common Issues

**Build fails:**
- Ensure `pyproject.toml` is correctly formatted
- Check that all required files are included in the source tree
- Verify Python version compatibility (>=3.8)

**Upload fails (403 Forbidden):**
- Check that your PyPI API token is valid
- Ensure you have permission to upload to the `noiseframework` package
- Verify you're not re-uploading an existing version

**Package doesn't install correctly:**
- Check `entry_points` in `pyproject.toml` for CLI
- Verify package structure with `python -m zipfile -l dist/*.whl`
- Test in clean virtual environment

**Version conflicts:**
- Ensure all version numbers match across files
- Check that the version doesn't already exist on PyPI
- Clear old build artifacts before rebuilding

## Quick Reference

```powershell
# Complete release in one go (version 1.2.0 example)
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path noiseframework.egg-info) { Remove-Item -Recurse -Force noiseframework.egg-info }
python -m build
python -m twine check dist/*
python -m twine upload dist/noiseframework-1.2.0* -u __token__ -p YOUR_TOKEN_HERE
git tag -a v1.2.0 -m "Release version 1.2.0"
git push origin v1.2.0
```

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.