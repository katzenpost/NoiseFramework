# Copilot Instructions – NoiseFramework

These are **project-wide instructions** for GitHub Copilot working on **NoiseFramework**, a professional open-source implementation of the Noise Protocol Framework in Python. 

NoiseFramework must be:
- **Correct** (cryptographically and spec-compliant)
- **Secure by default**
- **Easy to use** (simple Python API + simple CLI)
- **Well-documented & well-tested**
- **Available as a PIP library and a CLI tool**


---

## 1. General Behaviour

1. **Treat this as a professional open-source project.**  
   - Prefer clarity, safety, and maintainability over cleverness.
   - Avoid “quick hacks” and “toy” code unless explicitly requested for examples.

2. **ALWAYS read existing code, tests, and docs before generating new code.**  
   - Follow existing patterns, naming conventions, and structure.
   - Reuse existing helpers instead of re-inventing them.

3. **DO NOT invent features, commands, or APIs that don’t exist yet.**  
   - If the user asks for something ambiguous, extend the current style and design.
   - When adding a new public API, keep it minimal and coherent with the rest.

4. **DO NOT create new files unless explicitly asked.**  
   - Especially be careful with documentation (see section 3. Documentation Rules).

5. **Security and cryptography are first-class.**  
   - Follow the Noise spec and cryptographic best practices.
   - Prefer well-established primitives from libraries like `cryptography` or `libsodium` bindings.
   - Never roll your own primitive (e.g. custom hash, block cipher, PRNG) unless the project already does so in a clearly vetted module.

---

## 2. Code Style & Structure

1. **Language & Style**
   - Use **Python 3** with **type hints** everywhere (including return types).
   - Follow PEP8, with typical modern Python style:
     - `snake_case` for functions and variables
     - `PascalCase` for classes
   - Keep functions small and focused; prefer composition over long functions.

2. **Modules & Layout**
   - Respect the existing package layout (e.g. `py_noise/`, `py_noise/noise/`, `py_noise/transport/`, etc., if present).
   - Add new modules only where they logically belong.
   - Avoid placing unrelated utilities into core protocol files.

3. **Public API**
   - Public APIs should be:
     - Simple, obvious, and hard to misuse.
     - Prefer explicit parameters over magic behaviour.
   - For example, the typical usage should look something like:
     ```python
     from noiseframework import NoiseHandshake

     hs = NoiseHandshake("Noise_XX_25519_ChaChaPoly_SHA256")
     hs.initiator_handshake_step(...)
     transport = hs.to_transport()
     transport.send(b"hello")
     ```
   - When you add new high-level helpers, also provide **short, clear examples** in the documentation.

4. **Error Handling**
   - Fail fast and explicitly on invalid parameters (e.g., invalid Noise pattern string).
   - Raise clear, project-specific exceptions rather than generic `Exception` where possible.
   - Input validation is mandatory at public boundaries (API/CLI).

---

## 3. Documentation Rules (IMPORTANT)

1. **CRITICAL: DO NOT CREATE NEW MARKDOWN FILES.**
   - **Never** create new `.md` files for:
     - Setup instructions
     - Design notes
     - API docs
     - Release notes
   - Only modify existing Markdown files (e.g. `README.md`, existing docs in `docs/`, etc.).

2. **CHANGELOG Management**
   - **EVERY change** that modifies behaviour, API, structure, or tooling **must be documented in `docs/CHANGELOG.md`.**
   - Use a consistent, professional style (e.g. Keep a Changelog-like):
     - `Added`, `Changed`, `Fixed`, `Removed`, etc.
   - For each change you make, add a short bullet under the appropriate version or under an `[Unreleased]` section, e.g.:
     ```markdown
     ### Added
     - Implemented `NoiseHandshake.to_transport()` and added basic transport tests.
     ```

3. **No temporary or “notes” markdown**
   - Do **not** generate temporary instructions as new `.md` files.
   - If instructions are needed, integrate them into:
     - Existing documentation (e.g. `README.md`, existing `docs/*.md`), and
     - `docs/CHANGELOG.md` for change descriptions.

4. **Examples & Snippets**
   - Code examples in docs should be **minimal, realistic, and runnable**.
   - Avoid mock endpoints or irrelevant fake data; only small, focused examples.

---

## 4. Data & Mocking Rules

1. **NO mock data in production code.**
   - Do not add embedded “dummy users”, “fake hostnames”, or similar.
   - Do not leave debug keys or hard-coded secrets anywhere.

2. **Mocking is allowed only in tests.**
   - In test code, use realistic but safe mock data where needed.
   - Do not leak real credentials or live endpoints.
   - Use internal fixtures and factories for test keys and messages.

---

## 5. Testing Requirements (MANDATORY)

1. **Every feature must have tests.**
   - AFTER adding or modifying a feature, create or update tests **in the same PR / change set**.
   - Use `pytest` style if the project already does; follow whatever testing framework exists.

2. **Test Locations**
   - Place tests in the appropriate `tests/` submodule (e.g. `tests/test_handshake.py`, `tests/test_transport.py`).
   - Mirror the package structure in tests where possible.

3. **Test Types**
   - Write **unit tests** for:
     - Handshake logic
     - Pattern parsing
     - Key derivation and state transitions
     - Transport encryption/decryption
   - Where relevant, use **property-based tests** (e.g., with `hypothesis`) for protocol-level invariants (if already used in the project).

4. **Whenever adding a new public API**, at minimum:
   - Add tests that:
     - Cover the success path
     - Cover 1–2 relevant failure paths (e.g., invalid pattern, wrong key, invalid state).

5. **Keep tests fast and deterministic.**
   - Avoid slow network calls or external dependencies.
   - Use deterministic key seeds or fixed test vectors when possible.

---

## 6. CLI & Developer Experience

1. **Command-Line Interface**
   - If extending the CLI, keep commands **simple and predictable**.
   - Aim for intuitive commands such as:
     ```bash
     noiseframework handshake --pattern Noise_XX_25519_ChaChaPoly_SHA256
     noiseframework encrypt --in file --out file.enc
     noiseframework decrypt --in file.enc --out file
     ```
   - Use clear, descriptive help messages and `--help` output.

2. **Developer-Facing UX**
   - Write code that is easy to use from a REPL or script:
     - Straightforward constructors
     - Methods that do one job well
   - When adding developer-facing utilities, provide:
     - Short example in existing docs
     - A brief mention in `docs/CHANGELOG.md`

---

## 7. Cryptography & Protocol-Specific Guidance

1. **Noise Protocol Compliance**
   - Follow the official Noise Protocol Framework specification for:
     - Handshake patterns (e.g. `NN`, `IK`, `XX`, etc.)
     - Token sequences (`e`, `s`, `ee`, `es`, `se`, `ss`)
     - Transcript hashing and key derivation.

2. **Primitives**
   - Use only well-known primitives from vetted libraries (`cryptography`, `libsodium` bindings, etc.), unless the project defines its own wrappers.
   - Do not design new primitives.
   - Prefer:
     - `curve25519` (X25519) for DH where appropriate
     - `ChaCha20-Poly1305` or `AES-GCM` for AEAD
     - `SHA-256` / `BLAKE2` as specified by the project.

3. **Key Handling**
   - Treat keys and secrets as sensitive:
     - Avoid logging them.
     - Avoid printing them in exceptions.
     - Do not write them to disk unless part of a well-defined API.

4. **State Machines**
   - Protocol state transitions must be explicit and robust.
   - Disallow invalid transitions and raise clear exceptions when the protocol is misused.

---

## 8. Refactoring & Maintenance

1. **When refactoring:**
   - Preserve existing public APIs unless explicitly asked to change them.
   - Update tests accordingly and ensure coverage does not regress.
   - Document any behavioral changes in `docs/CHANGELOG.md`.

2. **Adding Dependencies**
   - Do not add new dependencies unless necessary.
   - Prefer small, well-maintained, security-focused libraries.
   - If you add a dependency, update:
     - The relevant config (`pyproject.toml` or similar).
     - `docs/CHANGELOG.md` with a note under `Added`.

---

## 9. Summary of Hard Rules (for Copilot)

- **NEVER create new Markdown files.**
- **ALWAYS log changes in `docs/CHANGELOG.md`.**
- **ALWAYS add or update tests whenever you add or change a feature.**
- **NO mock data in production code (only in tests).**
- **Follow existing project conventions, layout, and style.**
- **Treat NoiseFramework as a serious, professional cryptographic project.**
