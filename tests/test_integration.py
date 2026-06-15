import unittest
from src.utils.signatures import HybridSignatureEngine
from src.utils.serialization import NetworkPacketSerializer
from cryptography.hazmat.primitives.asymmetric import ed25519

class TestHybridFrameworkIntegration(unittest.TestCase):
    def test_end_to_end_pipeline(self):
        sig_engine = HybridSignatureEngine()
        message = b"Secure quantum-resistant transaction data payload."
        
        # 1. Key Generation
        keys = sig_engine.generate_keypair()
        
        # 2. Sign message
        signature = sig_engine.sign(message, keys["classical_private"], keys["pqc_private"])
        
        # 3. Serialize for "network transmission"
        classical_pub_bytes = keys["classical_public"].public_bytes_raw()
        wire_packet = NetworkPacketSerializer.pack_payload(
            encrypted_data=b"mock_ciphertext", 
            iv=b"123456789012", 
            hybrid_signature=signature, 
            classical_pub_bytes=classical_pub_bytes, 
            pqc_pub_bytes=keys["pqc_public"]
        )
        
        # 4. Unpack on the receiving end
        unpacked = NetworkPacketSerializer.unpack_payload(wire_packet)
        
        # 5. Extract keys and verify signatures (FIXED METHOD HERE)
        recovered_classical_pub = ed25519.Ed25519PublicKey.from_public_bytes(unpacked["classical_key"])
        
        is_valid = sig_engine.verify(
            message, 
            unpacked["signature"], 
            recovered_classical_pub, 
            unpacked["pqc_key"]
        )
        
        self.assertTrue(is_valid)

if __name__ == "__main__":
    unittest.main()
