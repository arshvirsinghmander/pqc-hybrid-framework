import json
import base64

class NetworkPacketSerializer:
    @staticmethod
    def pack_payload(encrypted_data: bytes, iv: bytes, hybrid_signature: bytes, classical_pub_bytes: bytes, pqc_pub_bytes: bytes) -> bytes:
        """Encodes binary cryptographic assets into a clean, network-safe JSON wire format."""
        packet = {
            "ciphertext": base64.b64encode(encrypted_data).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "signature": base64.b64encode(hybrid_signature).decode('utf-8'),
            "classical_key": base64.b64encode(classical_pub_bytes).decode('utf-8'),
            "pqc_key": base64.b64encode(pqc_pub_bytes).decode('utf-8')
        }
        return json.dumps(packet).encode('utf-8')

    @staticmethod
    def unpack_payload(packet_bytes: bytes) -> dict:
        """Parses the wire format back into raw operational bytes."""
        packet = json.loads(packet_bytes.decode('utf-8'))
        return {
            "ciphertext": base64.b64decode(packet["ciphertext"]),
            "iv": base64.b64decode(packet["iv"]),
            "signature": base64.b64decode(packet["signature"]),
            "classical_key": base64.b64decode(packet["classical_key"]),
            "pqc_key": base64.b64decode(packet["pqc_key"])
        }
