from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec

def generate_ecdsa_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def generate_keys():
    key = RSA.generate(2048)
    return key

def hash_data(data):
    h = MD5.new()
    h.update(data)
    return h.digest()

def encrypt_data(data, k):
    cipher = AES.new(k, AES.MODE_GCM)
    return cipher.encrypt(data)

def exchange_key():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters
