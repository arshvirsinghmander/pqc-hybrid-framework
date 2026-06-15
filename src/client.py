import asyncio
import base64
import json
from src.engine.hybrid import HybridCryptoCore
from src.utils.signatures import HybridSignatureEngine
from src.utils.serialization import NetworkPacketSerializer
from cryptography.hazmat.primitives.asymmetric import ed25519

class PQCHybridClient:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.crypto_core = HybridCryptoCore()
        self.sig_engine = HybridSignatureEngine()

    async def connect_and_transmit(self):
        print(f"[*] Initiating connection to secure gateway at {self.host}:{self.port}...")
        reader, writer = await asyncio.open_connection(self.host, self.port)

        try:
            # 1. Generate local composite ephemeral keypair bundles
            private_keys, public_bundle = self.crypto_core.generate_composite_handshake_keys()

            # 2. Send Client Hello over the wire
            handshake_packet = NetworkPacketSerializer.pack_payload(
                encrypted_data=b"", 
                iv=b"", 
                hybrid_signature=b"", 
                classical_pub_bytes=public_bundle["classical_bytes"], 
                pqc_pub_bytes=public_bundle["pqc_bytes"]
            )
            writer.write(handshake_packet)
            await writer.drain()
            print("[+] Client Hello sent successfully.")

            # 3. Read complete response payload from server
            response_raw = await reader.read(16384)
            split_bytes = response_raw.split(b"||SPLIT||")
            
            metadata_bundle = json.loads(split_bytes[0].decode('utf-8'))
            server_data = NetworkPacketSerializer.unpack_payload(split_bytes[1])

            # Decode internal transport fields
            ephem_cl_pub = base64.b64decode(metadata_bundle["ephem_cl_pub"])
            pqc_ciphertext = base64.b64decode(metadata_bundle["pqc_ciphertext"])

            # 4. Enforce strict Dual-Signature validation to verify Identity Authenticity
            recovered_server_classical_pub = ed25519.Ed25519PublicKey.from_public_bytes(server_data["classical_key"])
            handshake_signature_bytes = ephem_cl_pub + pqc_ciphertext + server_data["ciphertext"]
            
            is_identity_authentic = self.sig_engine.verify(
                handshake_signature_bytes,
                server_data["signature"],
                recovered_server_classical_pub,
                server_data["pqc_key"]
            )

            if not is_identity_authentic:
                print("[⚠️ SECURITY ALERT] Cryptographic signature validation failed! Dropping connection.")
                return

            print("[+] Server identity verified via ML-DSA-65 and Ed25519.")

            # 5. Execute hybrid decryption/decapsulation to extract the message
            payload_package = {
                "ephem_cl_pub": ephem_cl_pub,
                "pqc_ciphertext": pqc_ciphertext,
                "nonce": server_data["iv"],
                "ciphertext": server_data["ciphertext"]
            }

            decrypted_session_plaintext = self.crypto_core.hybrid_decrypt(private_keys, payload_package)
            print(f"[💥 SUCCESS] Decrypted Session Data: {decrypted_session_plaintext.decode('utf-8')}")
            print("[+] Quantum-secure tunnel successfully negotiated.")

        except Exception as e:
            print(f"[-] Connection aborted due to execution processing exception: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(PQCHybridClient().connect_and_transmit())
