from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from src.engine.classical import ClassicalEngine
from src.engine.pqc import PQCEngine

class HybridCryptoCore:
    def __init__(self):
        self.pqc = PQCEngine()
        self.classical = ClassicalEngine()

    def generate_composite_handshake_keys(self):
        cl_priv, cl_pub = self.classical.generate_x25519_keypair()
        pqc_priv, pqc_pub = self.pqc.generate_kem_keypair()
        
        cl_pub_bytes = cl_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_bundle = {
            "classical_bytes": cl_pub_bytes,
            "pqc_bytes": pqc_pub
        }
        return (cl_priv, pqc_priv), public_bundle

    def hybrid_combine_and_encrypt(self, receiver_public_bundle: dict, data: bytes):
        peer_cl_pub = serialization.load_der_public_key(receiver_public_bundle["classical_bytes"])
        ephem_priv, ephem_pub = self.classical.generate_x25519_keypair()
        classical_secret = self.classical.compute_ecdh_secret(ephem_priv, peer_cl_pub)
        
        ephem_cl_pub_bytes = ephem_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pqc_ciphertext, pqc_secret = self.pqc.encapsulate(receiver_public_bundle["pqc_bytes"])

        combined_raw_secret = classical_secret + pqc_secret
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"Hybrid-PQC-KEM-Derivation-v1"
        )
        composite_aes_key = hkdf.derive(combined_raw_secret)

        ciphertext, nonce = self.classical.encrypt_aes_gcm(data, composite_aes_key)

        payload_package = {
            "ephem_cl_pub": ephem_cl_pub_bytes,
            "pqc_ciphertext": pqc_ciphertext,
            "nonce": nonce,
            "ciphertext": ciphertext
        }
        return payload_package

    def hybrid_decrypt(self, private_keys: tuple, payload: dict) -> bytes:
        cl_priv, pqc_priv = private_keys

        peer_ephem_cl = serialization.load_der_public_key(payload["ephem_cl_pub"])
        classical_secret = self.classical.compute_ecdh_secret(cl_priv, peer_ephem_cl)

        pqc_secret = self.pqc.decapsulate(payload["pqc_ciphertext"], pqc_priv)

        combined_raw_secret = classical_secret + pqc_secret
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"Hybrid-PQC-KEM-Derivation-v1"
        )
        composite_aes_key = hkdf.derive(combined_raw_secret)

        return self.classical.decrypt_aes_gcm(payload["ciphertext"], payload["nonce"], composite_aes_key)
