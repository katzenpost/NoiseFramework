#!/usr/bin/env python3
"""Script to update test files with new exception types."""

import re
from pathlib import Path

# Test files to update
test_files = [
    'tests/test_cipher.py',
    'tests/test_dh.py', 
    'tests/test_hash.py',
    'tests/test_pattern.py',
    'tests/test_state.py',
    'tests/test_handshake.py',
    'tests/test_framing.py',
    'tests/test_transport.py',
    'tests/test_logging.py',
    'tests/test_cli.py'
]

# Exception import block to add
exception_imports = """from noiseframework.exceptions import (
    AuthenticationError, CryptoError, InvalidKeySizeError,
    UnsupportedPrimitiveError, UnsupportedPatternError,
    ValidationError, RoleNotSetError, RoleAlreadySetError,
    WrongTurnError, HandshakeCompleteError, MissingKeyError,
    NoKeySetError, NonceOverflowError
)"""

# Specific exception replacements (order matters - most specific first)
replacements = [
    ('pytest.raises(ValueError, match="Decryption failed")', 'pytest.raises(AuthenticationError)'),
    ('pytest.raises(ValueError, match="Key must be 32 bytes")', 'pytest.raises(InvalidKeySizeError)'),
    ('pytest.raises(ValueError, match="Cipher key must be")', 'pytest.raises(InvalidKeySizeError)'),
    ('pytest.raises(ValueError, match="Private key must be")', 'pytest.raises(InvalidKeySizeError)'),
    ('pytest.raises(ValueError, match="Public key must be")', 'pytest.raises(InvalidKeySizeError)'),
    ('pytest.raises(ValueError, match="Nonce must be")', 'pytest.raises(CryptoError)'),
    ('pytest.raises(ValueError, match="num_outputs must be")', 'pytest.raises(CryptoError)'),
    ('pytest.raises(ValueError, match="Unknown cipher")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Unknown DH")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Unknown hash")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Unsupported handshake pattern")', 'pytest.raises(UnsupportedPatternError)'),
    ('pytest.raises(ValueError, match="Unsupported DH function")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Unsupported cipher function")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Unsupported hash function")', 'pytest.raises(UnsupportedPrimitiveError)'),
    ('pytest.raises(ValueError, match="Invalid pattern")', 'pytest.raises(UnsupportedPatternError)'),
    ('pytest.raises(ValueError, match="Unknown handshake pattern")', 'pytest.raises(UnsupportedPatternError)'),
    ('pytest.raises(ValueError, match="Cannot encrypt: no key set")', 'pytest.raises(NoKeySetError)'),
    ('pytest.raises(ValueError, match="Cannot decrypt: no key set")', 'pytest.raises(NoKeySetError)'),
    ('pytest.raises(ValueError, match="Role already set")', 'pytest.raises(RoleAlreadySetError)'),
    ('pytest.raises(ValueError, match="max_message_size")', 'pytest.raises(ValidationError)'),
    # Generic ValueError - must be last
    ('pytest.raises(ValueError)', 'pytest.raises((RoleNotSetError, RoleAlreadySetError, WrongTurnError, HandshakeCompleteError, ValidationError, UnsupportedPatternError, MissingKeyError, NoKeySetError, InvalidKeySizeError))'),
]

for test_file in test_files:
    path = Path(test_file)
    if not path.exists():
        print(f'Skipping {test_file} - file not found')
        continue
    
    content = path.read_text(encoding='utf-8')
    
    # Check if already has imports
    if 'from noiseframework.exceptions import' in content:
        print(f'Skipping {test_file} - already updated')
        continue
    
    # Add exception imports after pytest import
    if 'import pytest' in content:
        content = content.replace('import pytest', f'import pytest\n{exception_imports}', 1)
    
    # Apply specific replacements
    for old, new in replacements:
        content = content.replace(old, new)
    
    path.write_text(content, encoding='utf-8')
    print(f'✓ Updated {test_file}')

print('\n✓ All test files updated successfully!')
