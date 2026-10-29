import hashlib

def verify_sha256(filename, expected_hash):
    try:
        with open(filename, 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
            return digest == expected_hash
    except FileNotFoundError:
        return False

if __name__ == "__main__":
    print("Audit starting...")
