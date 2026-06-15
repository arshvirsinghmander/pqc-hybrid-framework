import unittest
from src.engine.hybrid import HybridCryptoCore

class TestHybridFramework(unittest.TestCase):
    def setUp(self):
        self.core = HybridCryptoCore()
        self.sample_plaintext = b"Testing secure hybrid key exchange encapsulation protocols."

    def test_end_to_end_encryption_roundtrip(self):
        # 1. Generate multi-algorithm cryptographic parameters
        receiver_privs, receiver_pub_bundle = self.core.generate_composite_handshake_keys()
        
        # 2. Encrypt sample payload data using public bundle
        payload_package = self.core.hybrid_combine_and_encrypt(receiver_pub_bundle, self.sample_plaintext)
        
        # 3. Decrypt payload package using corresponding private parameters
        decrypted_plaintext = self.core.hybrid_decrypt(receiver_privs, payload_package)
        
        # 4. Enforce exact byte matches across the pipeline
        self.assertEqual(decrypted_plaintext, self.sample_plaintext)

if __name__ == '__main__':
    unittest.main()
