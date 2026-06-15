import oqs
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class HybridSignatureEngine:
    def __init__(self):
        # Initialize ML-DSA-65 from liboqs
        self.pqc_mechanism = "ML-DSA-65"
        
    def generate_keypair(self):
        """Generates both classical and quantum-resistant signing keys."""
        # Classical Ed25519
        classical_private = ed25519.Ed25519PrivateKey.generate()
        classical_public = classical_private.public_key()
        
        # Post-Quantum ML-DSA-65
        with oqs.Signature(self.pqc_mechanism) as signer:
            pqc_public = signer.generate_keypair()
            pqc_private = signer.export_secret_key()
            
        return {
            "classical_private": classical_private,
            "classical_public": classical_public,
            "pqc_private": pqc_private,
            "pqc_public": pqc_public
        }

    def sign(self, message: bytes, classical_private, pqc_private) -> bytes:
        """Signs data using BOTH schemes and concatenates the signatures."""
        # 1. Classical signature (64 bytes)
        classical_sig = classical_private.sign(message)
        
        # 2. PQC signature (3309 bytes for ML-DSA-65)
        with oqs.Signature(self.pqc_mechanism, pqc_private) as signer:
            pqc_sig = signer.sign(message)
            
        # Prepend the length of the PQC signature as a 4-byte big-endian integer
        # for clean parsing during verification
        pqc_len = len(pqc_sig).to_bytes(4, byteorder='big')
        
        return classical_sig + pqc_len + pqc_sig

    def verify(self, message: bytes, hybrid_signature: bytes, classical_public, pqc_public) -> bool:
        """Verifies both signatures. Returns True only if BOTH are perfectly valid."""
        try:
            # Extract classical signature (first 64 bytes)
            classical_sig = hybrid_signature[:64]
            
            # Extract PQC signature length and payload
            pqc_len = int.from_bytes(hybrid_signature[64:68], byteorder='big')
            pqc_sig = hybrid_signature[68:68+pqc_len]
            
            # 1. Verify Classical Layer
            classical_public.verify(classical_sig, message)
            
            # 2. Verify PQC Layer
            with oqs.Signature(self.pqc_mechanism) as verifier:
                is_pqc_valid = verifier.verify(message, pqc_sig, pqc_public)
                
            return is_pqc_valid
        except (InvalidSignature, Exception):
            return False
