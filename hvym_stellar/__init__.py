"""Heavymeta Stellar Utilities for Python , By: Fibo Metavinci"""

__version__ = "0.03"

import nacl
from nacl import utils, secret
from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey, Box, EncryptedMessage
from stellar_sdk import Keypair
from pymacaroons import Macaroon, Verifier
import hashlib
import secrets
import base64
from enum import Enum


class Stellar25519KeyPair:
    def __init__(self, keyPair : Keypair):
        self._base_keypair = keyPair
        self._raw_secret = keyPair.raw_secret_key()
        self._signing_key = SigningKey(self._raw_secret)
        self._private = self._signing_key.to_curve25519_private_key()
        self._public = self._signing_key.verify_key.to_curve25519_public_key()

    def base_stellar_keypair(self) -> Keypair:
        return self._base_keypair

    def signing_key(self) -> SigningKey:
        return self._signing_key
    
    def public_key_raw(self) -> PublicKey:
        return self._public
    
    def public_key(self):
        return base64.urlsafe_b64encode(self.public_key_raw().encode()).decode("utf-8")
    
    def private_key(self) -> PrivateKey:
        return self._private

class StellarSharedKey:
    def __init__(self, senderKeyPair : Stellar25519KeyPair, recieverPub : str):
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        self._hasher = hashlib.sha256()
        self._private = senderKeyPair.private_key()
        self._raw_pub = base64.urlsafe_b64decode(recieverPub.encode("utf-8"))
        self._box = Box(self._private, PublicKey(self._raw_pub))

    def nonce(self) -> bytes:
        return nacl.encoding.HexEncoder.encode(self._nonce).decode('utf-8')
    
    def shared_secret(self) -> bytes:
        return self._box.shared_key()
    
    def shared_secret_as_hex(self) -> str:
        return nacl.encoding.HexEncoder.encode(self.shared_secret()).decode('utf-8')
    
    def hash_of_shared_secret(self):
        self._hasher.update(self.shared_secret())
        return self._hasher.hexdigest()
    
    def encrypt(self, text : bytes) -> EncryptedMessage:
        return self._box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder)
    
    def encrypt_as_ciphertext (self, text  : bytes) -> bytes:
        return self.encrypt(text).ciphertext
    
    def encrypt_as_ciphertext_text (self, text  : bytes) -> str:
        return self.encrypt_as_ciphertext(text).decode('utf-8')
    

class StellarSharedDecryption:
    def __init__(self, recieverKeyPair : Stellar25519KeyPair, senderPub : str):
        self._hasher = hashlib.sha256()
        self._private = recieverKeyPair.private_key()
        self._raw_pub = base64.urlsafe_b64decode(senderPub.encode("utf-8"))
        self._box = Box(self._private, PublicKey(self._raw_pub))

    def shared_secret(self) -> bytes:
        return self._box.shared_key()
    
    def shared_secret_as_hex(self) -> str:
        return nacl.encoding.HexEncoder.encode(self.shared_secret()).decode('utf-8')
    
    def hash_of_shared_secret(self):
        self._hasher.update(self.shared_secret())
        return self._hasher.hexdigest()
    
    def decrypt(self, text : bytes) -> bytes:
        return self._box.decrypt(text, encoder=nacl.encoding.HexEncoder)
    
    def decrypt_as_text(self, text  : bytes) -> str:
        return self.decrypt(text).decode('utf-8')
    
class TokenType(Enum):
    ACCESS = 1
    SECRET = 2
    
class StellarSharedKeyTokenBuilder:
    def __init__(self, senderKeyPair : Stellar25519KeyPair, recieverPub : str, token_type : TokenType = TokenType.ACCESS, caveats : dict = None, secret : str = None):
        self._shared_encryption = StellarSharedKey(senderKeyPair, recieverPub)
        self._token = Macaroon(
            location=token_type.name,
            identifier=senderKeyPair.public_key(),
            key=self._shared_encryption.hash_of_shared_secret()
        )
        if token_type == TokenType.SECRET and secret != None:
            encrypted = self._shared_encryption.encrypt(secret.encode('utf-8'))
            self._token = Macaroon(
                location=token_type.name,
                identifier=senderKeyPair.public_key()+'|'+base64.urlsafe_b64encode(encrypted).decode('utf-8'),
                key=self._shared_encryption.hash_of_shared_secret()
            )

        if caveats != None:
            for key, value in caveats.items():
                self._token.add_first_party_caveat(f'{key} = {value}')

    def serialize(self) -> str:
        return self._token.serialize()
    
    def inspect(self) -> str:
        return self._token.inspect()
    
class StellarSharedKeyTokenVerifier:
    def __init__(self, recieverKeyPair : Stellar25519KeyPair, serializedToken: bytes, token_type : TokenType = TokenType.ACCESS, caveats : dict = None):
        self._token = Macaroon.deserialize(serializedToken)
        self._location = token_type.name
        self._sender_pub = self._token.identifier
        self._sender_secret = None
        self._verifier = Verifier()
        if '|' in self._token.identifier and  token_type == TokenType.SECRET:
            self._sender_pub = self._token.identifier.split('|')[0]
            self._sender_secret = self._token.identifier.split('|')[1]

        self._shared_decryption = StellarSharedDecryption(recieverKeyPair, self._sender_pub)
        
        if caveats != None:
            for key, value in caveats.items():
                self._verifier.satisfy_exact(f'{key} = {value}')

    def valid(self) -> bool:
        result = True
        if self._token.location != self._location:
            result = False
        try:
            self._verifier.verify(self._token, self._shared_decryption.hash_of_shared_secret())
        except:
            result = False
        return result
    
    def secret(self) -> str:
        return self._shared_decryption.decrypt(base64.urlsafe_b64decode(self._sender_secret)).decode('utf-8')
