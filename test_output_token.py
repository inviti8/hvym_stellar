"""
Test that outputs a biscuit token for inspection.
"""

import base64
import hashlib
from datetime import datetime, timedelta, timezone

try:
    from biscuit_auth import KeyPair, BiscuitBuilder
    BISCUIT_AVAILABLE = True
except ImportError:
    BISCUIT_AVAILABLE = False


def create_and_output_token():
    """Create a biscuit token and output it for inspection."""
    if not BISCUIT_AVAILABLE:
        print("❌ Biscuit library not available")
        return
    
    # Create test data
    test_data = b"Hello, this is test file content for HVYMFileTTokens! " * 20  # ~1KB
    filename = "hvym_test_file.txt"
    
    # Encode file data as base64
    encoded_data = base64.b64encode(test_data).decode('utf-8')
    file_hash = hashlib.sha256(test_data).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    print("🔧 Creating biscuit token...")
    print(f"📁 Original file size: {len(test_data)} bytes")
    print(f"📋 Encoded data size: {len(encoded_data)} characters")
    print(f"🔐 File hash: {file_hash}")
    
    # Create biscuit keypair
    biscuit_keypair = KeyPair()
    
    # Create biscuit with file data in metadata
    builder = BiscuitBuilder(
        f'''
        resource("{filename}");
        file_hash("{file_hash}");
        file_size({len(test_data)});
        file_data("{encoded_data}");
        expires("{expires_at.isoformat()}");
        created("{datetime.now(timezone.utc).isoformat()}");
        '''
    )
    
    biscuit = builder.build(biscuit_keypair.private_key)
    token = biscuit.to_base64()
    
    print(f"\n🍪 BISCUIT TOKEN:")
    print("=" * 80)
    print(token)
    print("=" * 80)
    
    print(f"\n📊 Token Statistics:")
    print(f"Token length: {len(token)} characters")
    print(f"Token size: {len(token)} bytes")
    print(f"Compression ratio: {len(token) / len(test_data):.2f}x")
    
    # Save token to file for easy inspection
    with open("hvym_biscuit_token.txt", "w") as f:
        f.write(token)
    print(f"\n💾 Token saved to: hvym_biscuit_token.txt")
    
    # Also save the biscuit keypair for verification
    with open("hvym_biscuit_keypair.txt", "w") as f:
        f.write(f"Private: {biscuit_keypair.private_key.encode()}\n")
        f.write(f"Public: {biscuit_keypair.public_key.encode()}\n")
    print(f"🔑 Keypair saved to: hvym_biscuit_keypair.txt")
    
    return token, biscuit_keypair


def inspect_token_structure(token):
    """Try to inspect the token structure."""
    if not BISCUIT_AVAILABLE:
        return
    
    try:
        from biscuit_auth import Biscuit, AuthorizerBuilder, Rule
        
        print(f"\n🔍 INSPECTING TOKEN STRUCTURE:")
        print("-" * 50)
        
        # Try to parse token (this will fail without correct keypair, but let's see structure)
        print("Token appears to be valid base64")
        
        # Check if it's valid base64
        try:
            decoded = base64.b64decode(token)
            print(f"✅ Valid base64, decoded to {len(decoded)} bytes")
            
            # Look for protobuf markers
            if decoded.startswith(b'\x0a'):
                print("✅ Appears to be protobuf format (starts with 0x0a)")
            
        except Exception as e:
            print(f"❌ Base64 decode failed: {e}")
            
    except Exception as e:
        print(f"❌ Inspection failed: {e}")


if __name__ == "__main__":
    print("🧪 HVYM Biscuit Token Output Test")
    print("=" * 50)
    
    token, keypair = create_and_output_token()
    inspect_token_structure(token)
    
    print(f"\n🎯 Token ready for inspection!")
    print(f"You can now examine the token structure and verify it contains your file data.")
