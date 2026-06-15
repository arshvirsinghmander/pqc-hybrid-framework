import time
import numpy as np
import matplotlib.pyplot as plt
from src.engine.hybrid import HybridCryptoCore

def run_performance_pipeline(iterations=100):
    core = HybridCryptoCore()
    test_data = b"Enterprise-Sensitive-Payload-Data-Assets-Under-Audit-2026"
    
    keygen_latencies = []
    encryption_latencies = []
    decryption_latencies = []

    print(f"[*] Commencing {iterations} iterations of Hybrid PQC Benchmark pipeline...")

    for _ in range(iterations):
        t0 = time.perf_counter()
        privs, pub_bundle = core.generate_composite_handshake_keys()
        keygen_latencies.append(time.perf_counter() - t0)

        t1 = time.perf_counter()
        payload = core.hybrid_combine_and_encrypt(pub_bundle, test_data)
        encryption_latencies.append(time.perf_counter() - t1)

        t2 = time.perf_counter()
        _ = core.hybrid_decrypt(privs, payload)
        decryption_latencies.append(time.perf_counter() - t2)

    print("\n[+] Benchmark Metrics Complete:")
    print(f" - KeyGen Latency (Mean):   {np.mean(keygen_latencies)*1000:.4f} ms")
    print(f" - Encryption Latency (Mean): {np.mean(encryption_latencies)*1000:.4f} ms")
    print(f" - Decryption Latency (Mean): {np.mean(decryption_latencies)*1000:.4f} ms")

    operations = ['Key Generation', 'Hybrid Encrypt', 'Hybrid Decrypt']
    means = [np.mean(keygen_latencies)*1000, np.mean(encryption_latencies)*1000, np.mean(decryption_latencies)*1000]
    
    plt.figure(figsize=(8, 5))
    plt.bar(operations, means, color=['#1f77b4', '#2ca02c', '#d62728'], edgecolor='black')
    plt.ylabel('Latency (Milliseconds)')
    plt.title('Performance Metrics: Hybrid Classical + ML-KEM Cryptography Suite')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.savefig('pqc_performance_metrics.png', dpi=300)
    print("[+] Exported metrics performance analysis model to 'pqc_performance_metrics.png'")

if __name__ == '__main__':
    run_performance_pipeline()
