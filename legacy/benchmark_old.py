import os
import subprocess
import time
import secrets

def load_env_file(filepath=".env"):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")

load_env_file()
BIT_LENGTH = int(os.getenv("SECRET_BOUNDARY_BIT_LENGTH", "1024"))

def is_prime(n, k=40):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate): return candidate

def benchmark_python():
    start = time.perf_counter()
    p = generate_prime(BIT_LENGTH * 2)
    a = generate_prime(BIT_LENGTH)
    b = generate_prime(BIT_LENGTH)
    if a > b: a, b = b, a
    sum_key = a + b
    public_c = sum_key // 2
    secret_r = secrets.randbelow(p - 2) + 2
    k = (secret_r * pow(sum_key, -1, p)) % p
    blinded_A = (a * k) % p
    blinded_B = (b * k) % p
    v_sum = (blinded_A + blinded_B) % p
    v_med = (2 * public_c * k * pow(secret_r, -1, p)) % p
    end = time.perf_counter()
    return end - start

def benchmark_cpp():
    # Use absolute path for native binary as requested by environment setup
    bin_path = "C:/Users/tripp/GoldbachTrapdoor-PrimeCollapse/cpp_backend/prime_collapse_native"
    if not os.path.exists(bin_path):
        return None

    start = time.perf_counter()
    try:
        subprocess.run([bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        return None
    end = time.perf_counter()
    return end - start

def run_performance_suite(iterations=5):
    print(f"=== STARTING PRIMECOLLAPSE BENCHMARKING ENGINE ===")
    print(f"Evaluating {iterations} iterations at {BIT_LENGTH}-bit space...\n")
    
    py_times = []
    cpp_times = []
    
    for i in range(iterations):
        print(f"[*] Running cycle {i+1}/{iterations}...", end=" ")
        py_t = benchmark_python()
        py_times.append(py_t)
        cpp_t = benchmark_cpp()
        if cpp_t:
            cpp_times.append(cpp_t)
        print("Done")
        
    avg_py = sum(py_times) / iterations
    avg_cpp = sum(cpp_times) / len(cpp_times) if cpp_times else 0
    speedup = avg_py / avg_cpp if avg_cpp > 0 else 0

    print("\n================ PERFORMANCE MATRIX ================")
    print(f"Python Average Runtime : {avg_py:.5f} seconds")
    print(f"C++ Native Average     : {avg_cpp:.5f} seconds")
    if speedup > 0:
        print(f"Performance Multiplier : {speedup:.2f}x Faster Execution")
    else:
        print("C++ Native binary not found or failed to run.")
    print("====================================================")

if __name__ == "__main__":
    run_performance_suite()
