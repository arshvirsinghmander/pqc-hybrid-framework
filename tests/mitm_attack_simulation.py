import asyncio
from src.utils.serialization import NetworkPacketSerializer

class MitMAttackSimulation:
    def __init__(self, target_host='127.0.0.1', target_port=8080, listening_port=8081):
        self.target_host = target_host
        self.target_port = target_port
        self.listening_port = listening_port

    async def intercept_and_corrupt(self, reader, writer):
        print("\n[⚠️ MITM PROXY] Client connected to proxy interceptor zone.")
        try:
            # 1. Sniff client data
            client_handshake = await reader.read(16384)
            print("[⚠️ MITM PROXY] Intercepted Client Hello packet stream.")

            # 2. Forward clean client packet to legitimate server
            server_reader, server_writer = await asyncio.open_connection(self.target_host, self.target_port)
            server_writer.write(client_handshake)
            await server_writer.drain()

            # 3. Intercept Server Response Handshake
            server_response = await server_reader.read(16384)
            print("[⚠️ MITM PROXY] Intercepted Server Response frame down-line.")

            # 4. EXECUTE ACTIVE INJECTION ATTACK
            # Maliciously mutate bytes inside the serialized block to simulate a bit-flip or identity spoofing
            corrupted_response = bytearray(server_response)
            # Flip bytes near the end where encryption structures sit
            corrupted_response[-50] ^= 0xFF 
            print("[🔥 ATTACK INJECTED] Maliciously altered structural validation bytes inside the handshake packet stream.")

            # 5. Forward corrupt frame back to Client
            writer.write(bytes(corrupted_response))
            await writer.drain()
            
            server_writer.close()
            await server_writer.wait_closed()
        except Exception as e:
            print(f"[-] Proxy intercept sequence exception: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def run(self):
        proxy = await asyncio.start_server(self.intercept_and_corrupt, '127.0.0.1', self.listening_port)
        print(f"[💥 RED TEAM ACTIVE] Rogue Proxy active on port {self.listening_port}. Redirect client targets here to simulate attack vector.")
        async with proxy:
            await proxy.serve_forever()

if __name__ == "__main__":
    asyncio.run(MitMAttackSimulation().run())
