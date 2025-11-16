# PyPI Release Guide for py-noise

## Pre-Release Checklist

✅ All tests passing (156 tests, 92% coverage)
✅ README comprehensive and up-to-date
✅ CHANGELOG updated
✅ LICENSE file present
✅ Version number set in pyproject.toml (0.1.0)
✅ Distribution packages built
✅ Packages validated with twine

## Built Packages

- `dist/py_noise-0.1.0-py3-none-any.whl` (23.5 KB)
- `dist/py_noise-0.1.0.tar.gz` (36.8 KB)

## Upload to PyPI

### Test PyPI (Recommended First)

Upload to Test PyPI first to verify everything works:

```bash
# Upload to Test PyPI
python -m twine upload --repository testpypi dist/*

# Test installation from Test PyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ py-noise
```

### Production PyPI

Once verified on Test PyPI, upload to production:

```bash
# Upload to PyPI
python -m twine upload dist/*

# You will be prompted for:
# - Username: __token__
# - Password: pypi-... (your API token)
```

### API Token Setup

1. Go to https://pypi.org/manage/account/token/
2. Create a new API token
3. Scope: "Entire account" or "Project: py-noise"
4. Copy the token (starts with `pypi-`)
5. Use it as password when uploading

### Verify Installation

After upload, test the package:

```bash
# Install from PyPI
pip install py-noise

# Test CLI
py-noise --version
py-noise info

# Test Python API
python -c "from py_noise import NoiseHandshake; print('Success!')"
```

## Post-Release Steps

1. Tag the release in git:
   ```bash
   git tag -a v0.1.0 -m "Release version 0.1.0"
   git push origin v0.1.0
   ```

2. Create GitHub release:
   - Go to https://github.com/juliuspleunes4/py-noise/releases
   - Click "Create a new release"
   - Choose tag v0.1.0
   - Title: "v0.1.0 - Initial Release"
   - Description: Copy from CHANGELOG.md

3. Update CHANGELOG.md:
   - Change `[Unreleased]` to `[0.1.0] - 2025-11-16`
   - Add new `[Unreleased]` section

4. Bump version for development:
   - Update version in pyproject.toml to `0.1.1-dev`

## Troubleshooting

### Upload fails with "File already exists"

PyPI doesn't allow re-uploading the same version. You need to:
1. Bump the version number in pyproject.toml
2. Rebuild: `python -m build`
3. Upload again

### Import errors after installation

Make sure all __init__.py files are present and the package structure is correct.

### CLI command not found

The entry point is registered as `py-noise`. Make sure setuptools processes the `[project.scripts]` section correctly.
