import random
from math import gcd


class RSA:
    def __init__(self, bit_size=1024):
        self.bit_size = bit_size
        self.public_key = None
        self.private_key = None

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
            if n % p == 0:
                return n == p

        # write n-1 = d * 2^r
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self):
        while True:
            p = random.getrandbits(self.bit_size)
            p |= (1 << self.bit_size - 1) | 1
            if self.is_prime(p):
                return p

    def mod_inverse(self, e, phi):
        def extended_gcd(a, b):
            if b == 0:
                return (a, 1, 0)
            g, x1, y1 = extended_gcd(b, a % b)
            x = y1
            y = x1 - (a // b) * y1
            return (g, x, y)

        g, x, _ = extended_gcd(e, phi)
        if g != 1:
            raise Exception("No modular inverse")
        return x % phi

    def get_block_size(self):
        _, n = self.public_key
        return (n.bit_length() // 8) - 1

    def encrypt_file(self, input_path, output_path):
        if not self.public_key:
            raise ValueError("Public key not set")

        e, n = self.public_key
        block_size = self.get_block_size()

        with open(input_path, "rb") as f:
            data = f.read()

        encrypted_blocks = []

        for i in range(0, len(data), block_size):
            chunk = data[i:i + block_size]
            chunk_int = int.from_bytes(chunk, 'big')

            cipher = pow(chunk_int, e, n)
            encrypted_blocks.append(cipher)

        # Lưu dạng text (mỗi dòng 1 block)
        with open(output_path, "w") as f:
            for c in encrypted_blocks:
                f.write(str(c) + "\n")

    def decrypt_file(self, input_path, output_path):
        if not self.private_key:
            raise ValueError("Private key not set")

        d, n = self.private_key

        with open(input_path, "r") as f:
            encrypted_blocks = [int(line.strip()) for line in f]

        decrypted_data = b""

        for c in encrypted_blocks:
            m_int = pow(c, d, n)

            block_size = (n.bit_length() // 8) - 1
            chunk = m_int.to_bytes(block_size, 'big').lstrip(b'\x00')

            decrypted_data += chunk

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

    def generate_keys(self):
        print("Generating primes...")
        p = self.generate_prime()
        q = self.generate_prime()

        while p == q:
            q = self.generate_prime()

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if gcd(e, phi) != 1:
            e = random.randrange(2, phi)

        d = self.mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

        return self.public_key, self.private_key

    def encrypt(self, plaintext):
        e, n = self.public_key
        plaintext_bytes = plaintext.encode()
        plaintext_int = int.from_bytes(plaintext_bytes, 'big')

        if plaintext_int >= n:
            raise ValueError("Message too large for key size")

        cipher_int = pow(plaintext_int, e, n)
        return cipher_int

    def decrypt(self, ciphertext):
        d, n = self.private_key
        plain_int = pow(ciphertext, d, n)

        byte_length = (plain_int.bit_length() + 7) // 8
        plaintext_bytes = plain_int.to_bytes(byte_length, 'big')

        return plaintext_bytes.decode()

    def show_keys(self):
        print("\nPublic Key (e, n):")
        print(self.public_key)

        print("\nPrivate Key (d, n):")
        print(self.private_key)
