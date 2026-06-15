import asyncio
import base64
import json
from src.engine.hybrid import HybridCryptoCore
from src.utils.signatures import HybridSignatureEngine
from src.utils.serialization import NetworkPacketSerializer

class PQCHybridServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.crypto_core = HybridCryptoCore()
        self.sig_engine = HybridSignatureEngine()
        # Generate persistent server identity signing keys
        self.server_identity = self.sig_engine.generate_keypair()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"[*] Secure connection established with {addr}")

        try:
            # 1. Receive client's public bundle
            client_handshake_bytes = await reader.read(8192)
            if not client_handshake_bytes:
                return
            
            unpacked_client_hello = NetworkPacketSerializer.unpack_payload(client_handshake_bytes)
            print("[+] Received Client Hello containing public handshake keys.")

            # Reconstruct the bundle expected by hybrid_combine_and_encrypt
            receiver_public_bundle = {
                "classical_bytes": unpacked_client_hello["classical_key"],
                "pqc_bytes": unpacked_client_hello["pqc_key"]
            }

            # 2. Establish session secret and encrypt a message payload via core KEM engine
            secret_session_message = b"SERVER_AUTHENTICATED_SESSION_ESTABLISHED"
            payload_package = self.crypto_core.hybrid_combine_and_encrypt(receiver_public_bundle, secret_session_message)
            print("[+] Successfully derived hybrid shared keys and generated AES-GCM ciphertext.")

            # 3. Create a composite signature frame over the key exchange materials
            # This locks down the handshake data to prevent Man-in-the-Middle down-grade attacks
            handshake_signature_bytes = (
                payload_package["ephem_cl_pub"] + 
                payload_package["pqc_ciphertext"] + 
                payload_package["ciphertext"]
            )
            
            dual_signature = self.sig_engine.sign(
                handshake_signature_bytes,
                self.server_identity["classical_private"],
                self.server_identity["pqc_private"]
            )

            # 4. Serialize complete encrypted session state for transport
            # Pack nested metadata structural objects as safe b64 fields inside our packet
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

            # Prepend the transport bundle lengths so the client can unpack metadata safely
            writer.write(transport_ciphertext_bundle + b"||SPLIT||" + server_response_packet)
            await writer.drain()
            print("[+] Dispatched response packet. Cryptographic handshake completed successfully.")

        except Exception as e:
            print(f"[-] Cryptographic handshake processing failed for {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[*] Quantum-Resistant Hybrid Server listening on {self.host}:{self.port}...")
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(PQCHybridServer().start())
