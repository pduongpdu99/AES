from algo.aes import AES
from algo.mode.gcm import GCM

if __name__ == "__main__":
    with open("./keys/aes_key.txt", "r") as f:
        key = f.read().strip()

    aes = AES(key, mode=128)        # hoặc 192, 256

    gcm = GCM(aes)

    # Encrypt
    nonce, ct, tag = gcm.encrypt(
        "./data/aes_plaintext.txt", "./data/encrypted_gcm.bin")
    print(f"Nonce: {nonce}")
    print(f"Tag  : {tag}")

    # Decrypt
    try:
        gcm.decrypt("./data/encrypted_gcm.bin", "./data/decrypted_gcm.txt")
        print("Decrypt thành công!")
    except ValueError as e:
        print("Lỗi:", e)
