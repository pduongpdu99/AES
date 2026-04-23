from algo.rsa import RSA

rsa = RSA(bit_size=512)
rsa.generate_keys()

plaintext_path = "./data/rsa_plaintext.txt"
encrypted_path = "./data/encrypted_rsa.txt"
decrypted_path = "./data/decrypted_rsa.txt"

# Encrypt file
rsa.encrypt_file(plaintext_path, encrypted_path)
print("Encrypted done!")

# Decrypt file
rsa.decrypt_file(encrypted_path, decrypted_path)
print("Decrypted done!")
