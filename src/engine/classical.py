import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ClassicalEngine:
    @staticmethod
    def generate_x25519_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def compute_ecdh_secret(private_key, peer_public_key) -> bytes:
        return private_key.exchange(ec.ECDH(), peer_public_key)

    @staticmethod
    def encrypt_aes_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
