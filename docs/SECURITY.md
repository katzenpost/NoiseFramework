# Security Policy

## Supported Versions

The following versions of NoiseFramework are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in NoiseFramework, please report it privately to help protect users before the issue is made public.

### How to Report

1. **Email**: Send details to [your-email@example.com]
2. **Subject**: Use "SECURITY: NoiseFramework - [Brief Description]"
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (if applicable)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days with assessment and timeline
- **Fix Timeline**: Critical issues will be addressed within 30 days
- **Disclosure**: Coordinated disclosure after fix is released

### Security Considerations

NoiseFramework is a cryptographic library. When using it:

1. **Key Management**: Never hardcode private keys in your application
2. **Random Number Generation**: Ensure your system's RNG is properly seeded
3. **Pattern Selection**: Choose appropriate Noise patterns for your threat model:
   - Use `XX` for mutual authentication
   - Use `IK` when responder's public key is known
   - Avoid `NN` in production (no authentication)
4. **Dependencies**: Keep the `cryptography` library updated
5. **Side Channels**: Be aware this implementation has not been audited for side-channel resistance
6. **Protocol Version**: Ensure both parties use compatible NoiseFramework versions

### Cryptographic Implementations

NoiseFramework relies on the following cryptographic primitives:

- **DH**: Curve25519 (X25519), Curve448 (X448) via `cryptography`
- **AEAD**: ChaCha20-Poly1305, AES-256-GCM via `cryptography`
- **Hash**: SHA-256, SHA-512, BLAKE2s, BLAKE2b via `cryptography`

All primitives are provided by the well-vetted [pyca/cryptography](https://github.com/pyca/cryptography) library.

### Known Limitations

- **No formal security audit**: This library has not undergone professional cryptographic audit
- **Timing attacks**: Implementation prioritizes correctness over constant-time operations
- **Memory safety**: Python's memory management may leave sensitive data in memory
- **Educational purpose**: While production-ready, use in high-security environments should include additional review

### Security Updates

Security patches will be:
- Released as patch versions (e.g., 0.1.1)
- Documented in `docs/CHANGELOG.md`
- Announced via GitHub Security Advisories
- Tagged with appropriate CVE if applicable

### Acknowledgments

We appreciate the security research community's efforts in making NoiseFramework more secure. Reporters will be acknowledged in the `CHANGELOG.md` unless they prefer to remain anonymous.
