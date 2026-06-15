import asyncio
import base64
import json
import os
from src.engine.hybrid import HybridCryptoCore
from src.utils.signatures import HybridSignatureEngine
from src.utils.serialization import NetworkPacketSerializer

class PQCHybridFileServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.crypto_core = HybridCryptoCore()
        self.sig_engine = HybridSignatureEngine()
        self.server_identity = self.sig_engine.generate_keypair()
        self.output_directory = "./server_vault"
        os.makedirs(self.output_directory, exist_ok=True)

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"\n[*] Incoming connection from secure client at: {addr}")
        session_key = None
        message_count = 0

        try:
            # 1. Handshake Phase
            handshake_bytes = await reader.read(16384)
            if not handshake_bytes: return
            
            unpacked_client_hello = NetworkPacketSerializer.unpack_payload(handshake_bytes)
            receiver_public_bundle = {
                "classical_bytes": unpacked_client_hello["classical_key"],
                "pqc_bytes": unpacked_client_hello["pqc_key"]
            }

            handshake_ack_payload = b"INIT_SECURE_FILE_CHANNEL"
            payload_package = self.crypto_core.hybrid_combine_and_encrypt(receiver_public_bundle, handshake_ack_payload)
            session_key = payload_package["session_key"]

            handshake_signature_bytes = payload_package["ephem_cl_pub"] + payload_package["pqc_ciphertext"] + payload_package["ciphertext"]
            dual_signature = self.sig_engine.sign(handshake_signature_bytes, self.server_identity["classical_private"], self.server_identity["pqc_private"])

            transport_ciphertext_bundle = json.dumps({
                "ephem_cl_pub": base64.b64encode(payload_package["ephem_cl_pub"]).decode('utf-8'),
                "pqc_ciphertext": base64.b64encode(payload_package["pqc_ciphertext"]).decode('utf-8')
            }).encode('utf-8')

            server_response_packet = NetworkPacketSerializer.pack_payload(
                encrypted_data=payload_package["ciphertext"],
                iv=payload_package["nonce"],
                hybrid_signature=dual_signature,
                classical_pub_bytes=self.server_identity["classical_public"].public_bytes_raw(),
                pqc_pub_bytes=self.server_identity["pqc_public"]
            )

            writer.write(transport_ciphertext_bundle + b"||SPLIT||" + server_response_packet)
            await writer.drain()
            print("[+] Hybrid key negotiation completed. Secure Session established.")

            # 2. File Ingestion Phase
            metadata_bytes = await reader.read(4096)
            if not metadata_bytes: return
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            filename = os.path.basename(metadata["filename"])
            file_destination = os.path.join(self.output_directory, filename)
            
            print(f"[*] Readying system to receive encrypted file: {filename} ({metadata['file_size']} bytes)")

            with open(file_destination, "wb") as f:
                while True:
                    chunk_bytes = await reader.read(65536)
                    if not chunk_bytes or chunk_bytes == b"||EOF||":
                        break

                    # Enforce Session Key Rotation Protocol
                    # If message thresholds pass, seamlessly ratchet the key forward using previous state
                    if message_count > 0 and message_count % 3 == 0:
                        rotation_salt = b"ServerKeyRotationIncrement-" + str(message_count).encode()
                        session_key = self.crypto_core.rotate_session_key(session_key, rotation_salt)
                        print(f"[🔄 PFS] Symmetric session key rotated forward. Current Counter: {message_count}")

                    packet_data = NetworkPacketSerializer.unpack_payload(chunk_bytes)
                    
                    # Decrypt block using active session key state
                    decrypted_block = self.crypto_core.classical.decrypt_aes_gcm(
                        packet_data["ciphertext"],
                        packet_data["iv"],
                        session_key
                    )
                    f.write(decrypted_block)
                    message_count += 1

            print(f"[💥 SUCCESS] File successfully received, authenticated, and decrypted to vault: {file_destination}")

        except Exception as e:
            print(f"[-] Cryptographic transaction failed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[*] Asynchronous PQC Vault Storage Server listening on {self.host}:{self.port}...")
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(PQCHybridFileServer().start())
