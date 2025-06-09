from stellar_sdk import Keypair
from hvym_stellar import *


sender_stellar_kp = Keypair.random()
reciever_stellar_kp = Keypair.random()

##Stellar keys must be converted to be compatible
sender_kp = Stellar25519KeyPair(sender_stellar_kp)
reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)

print('public key:')
print(reciever_kp.public_key())

##Create the encryption object
sharedKey = StellarSharedKey(sender_kp, reciever_kp.public_key())
txt = b"some text to be encrypted"

encrypted = sharedKey.encrypt(txt)

##Create the decryption object
sharedDecrypt = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
##Decrypt
txt = sharedDecrypt.decrypt(encrypted)

print(txt)

##Token creation and verification
caveats = {
    'test' : 'pass'
}

##create a new token and serialize it
token = StellarSharedKeyToken(sender_kp, reciever_kp.public_key(), location="test", caveats=caveats)
serialized_token = token.serialize()

print(token.inspect())
print(serialized_token)

wrong_caveats = {
    'test' : 'test',
    'test' : 'fail'
}

##Create token verifier and check validity of token
tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, location="test", caveats=caveats)

print(tokenVerifier.valid())##>> True

tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, location="test", caveats=wrong_caveats)

print(tokenVerifier.valid())##>> False

tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, location="WRONG LOCATION", caveats=wrong_caveats)

print(tokenVerifier.valid())##>> False

##Try to use verify token with a different key
attacker_stellar_kp = Keypair.random()
attacker_kp = Stellar25519KeyPair(attacker_stellar_kp)

tokenVerifier = StellarSharedKeyTokenVerifier(attacker_kp, serialized_token, location="test", caveats=caveats)

print(tokenVerifier.valid())##>> False