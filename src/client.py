import asyncio
import base64
import json
import os
import sys
from src.engine.hybrid import HybridCryptoCore
from src.utils.signatures import HybridSignatureEngine
from src.utils.serialization import NetworkPacketSerializer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class PQCHybridFileClient:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.crypto_core = HybridCryptoCore()
        self.sig_engine = HybridSignatureEngine()

    async def transfer_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"[-] Error: Target file '{file_path}' does not exist.")
            return

        print(f"[*] Initiating connection to quantum-resistant gateway at {self.host}:{self.port}...")
        reader, writer = await asyncio.open_connection(self.host, self.port)
        session_key = None
        message_count = 0

        try:
            # 1. Handshake Phase
            private_keys, public_bundle = self.crypto_core.generate_composite_handshake_keys()
            handshake_packet = NetworkPacketSerializer.pack_payload(
                encrypted_data=b"", iv=b"", hybrid_signature=b"", 
                classical_pub_bytes=public_bundle["classical_bytes"], 
                pqc_pub_bytes=public_bundle["pqc_bytes"]
            )
            writer.write(handshake_packet)
            await writer.drain()

            response_raw = await reader.read(16384)
            split_bytes = response_raw.split(b"||SPLIT||")
            metadata_bundle = json.loads(split_bytes[0].decode('utf-8'))
            server_data = NetworkPacketSerializer.unpack_payload(split_bytes[1])

            ephem_cl_pub = base64.b64decode(metadata_bundle["ephem_cl_pub"])
            pqc_ciphertext = base64.b64decode(metadata_bundle["pqc_ciphertext"])

            # Verify dual entity infrastructure signatures
            recovered_server_classical_pub = ed25519.Ed25519PublicKey.from_public_bytes(server_data["classical_key"])
            handshake_signature_bytes = ephem_cl_pub + pqc_ciphertext + server_data["ciphertext"]
            
            if not self.sig_engine.verify(handshake_signature_bytes, server_data["signature"], recovered_server_classical_pub, server_data["pqc_key"]):
                print("[⚠️ SECURITY ALERT] Handshake validation failed! Dropping connections immediately.")
                return

            print("[+] Server identity verified via ML-DSA-65 & Ed25519.")

            # 5. Execute hybrid decryption/decapsulation to extract the initial session state
            payload_package = {
                "ephem_cl_pub": ephem_cl_pub,
                "pqc_ciphertext": pqc_ciphertext,
                "nonce": server_data["iv"],
                "ciphertext": server_data["ciphertext"]
            }

            # This natively computes ECDH, decapsulates ML-KEM, and returns the verified plaintext
            decrypted_init_signal = self.crypto_core.hybrid_decrypt(private_keys, payload_package)
            
            # Reconstruct the exact structural symmetric AES key state using your internal core KDF formula
            # Fetching the classical secret from the client's local ephemeral key agreement
            peer_ephem_cl = serialization.load_der_public_key(ephem_cl_pub)
            classical_secret = self.crypto_core.classical.compute_ecdh_secret(private_keys[0], peer_ephem_cl)
            pqc_secret = self.crypto_core.pqc.decapsulate(pqc_ciphertext, private_keys[1])
            session_key = self.crypto_core._derivation_kdf(classical_secret, pqc_secret)

            # 2. File Broadcast Phase
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            metadata_header = json.dumps({"filename": filename, "file_size": file_size}).encode('utf-8')
            writer.write(metadata_header)
            await writer.drain()

            print(f"[*] Streaming encrypted data blocks over wire...")
            with open(file_path, "rb") as f:
                while True:
                    file_block = f.read(4096)
                    if not file_block: break

                    if message_count > 0 and message_count % 3 == 0:
                        rotation_salt = b"ServerKeyRotationIncrement-" + str(message_count).encode()
                        session_key = self.crypto_core.rotate_session_key(session_key, rotation_salt)
                        print(f"[🔄 PFS] Key ratcheted forward symmetrically. Index: {message_count}")

                    cipher_block, nonce = self.crypto_core.classical.encrypt_aes_gcm(file_block, session_key)
                    transport_packet = NetworkPacketSerializer.pack_payload(
                        encrypted_data=cipher_block, iv=nonce, hybrid_signature=b"",
                        classical_pub_bytes=b"", pqc_pub_bytes=b""
                    )
                    writer.write(transport_packet)
                    await writer.drain()
                    message_count += 1

            writer.write(b"||EOF||")
            await writer.drain()
            print(f"[💥 SUCCESS] Secure upload completed for: {filename}")

        except Exception as e:
            print(f"[-] Execution pipeline halted: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        print("[-] Usage: python3 -m src.client <path_to_file>")
    else:
        asyncio.run(PQCHybridFileClient().transfer_file(target))

