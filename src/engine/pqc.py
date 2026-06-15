import oqs

class PQCEngine:
    def __init__(self, kem_name="Kyber768", sig_name="Dilithium3"):
        self.kem_name = kem_name
        self.sig_name = sig_name

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return private_key, public_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        # Pass the secret_key directly into the context manager constructor
        with oqs.KeyEncapsulation(self.kem_name, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
