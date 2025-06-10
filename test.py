from stellar_sdk import Keypair
from hvym_stellar import *


sender_stellar_kp = Keypair.random()
reciever_stellar_kp = Keypair.random()

##Stellar keys must be converted to be compatible format for ECDH
sender_kp = Stellar25519KeyPair(sender_stellar_kp)
reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)

print('public key:')
print(reciever_stellar_kp.public_key)
print(reciever_kp.public_key())

##Create the encryption object
sharedKey = StellarSharedKey(sender_kp, reciever_kp.public_key())
txt = sender_stellar_kp.secret.encode('utf-8')
print('original secret:')
print(txt)

encrypted = sharedKey.encrypt(txt)

##Create the decryption object
sharedDecrypt = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
##Decrypt
decrypted = sharedDecrypt.decrypt(encrypted)

print('decrypted secret:')
print(decrypted)

##Token creation and verification
caveats = {
    'test' : 'pass'
}

##create a new access token and serialize it
token = StellarSharedKeyTokenBuilder(sender_kp, reciever_kp.public_key(), token_type=TokenType.ACCESS, caveats=caveats)
serialized_token = token.serialize()

print(token.inspect())
print(serialized_token)

wrong_caveats = {
    'test' : 'test',
    'test' : 'fail'
}

##Create token verifier and check validity of token
tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.ACCESS, caveats=caveats)

print(tokenVerifier.valid())##>> True

tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.ACCESS, caveats=wrong_caveats)

print(tokenVerifier.valid())##>> False

tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.SECRET, caveats=caveats)

print(tokenVerifier.valid())##>> False

##Try to use verify token with a different key
attacker_stellar_kp = Keypair.random()
attacker_kp = Stellar25519KeyPair(attacker_stellar_kp)

tokenVerifier = StellarSharedKeyTokenVerifier(attacker_kp, serialized_token, token_type=TokenType.ACCESS, caveats=caveats)

print(tokenVerifier.valid())##>> False

##Create the decryption object
sharedDecrypt = StellarSharedDecryption(attacker_kp, sender_kp.public_key())
##Decrypt
try:
    txt = sharedDecrypt.decrypt(encrypted)
    print(txt)
except:
    print('Cant Decrypt!!')

##create a new secret token and serialize it
abstract_acct_stellar_kp = Keypair.random()
abstract_acct_kp = Stellar25519KeyPair(abstract_acct_stellar_kp)
token = StellarSharedKeyTokenBuilder(sender_kp, abstract_acct_kp.public_key(), token_type=TokenType.SECRET, caveats=caveats, secret=abstract_acct_stellar_kp.secret)
serialized_token = token.serialize()

print(token.inspect())
print(serialized_token)

##Create token verifier and check validity of token and retrieve it's secret
tokenVerifier = StellarSharedKeyTokenVerifier(abstract_acct_kp, serialized_token, token_type=TokenType.SECRET, caveats=caveats)

print(tokenVerifier.valid())##>> True
print('Do secrets match?:')
print(abstract_acct_stellar_kp.secret)
print(tokenVerifier.secret())

