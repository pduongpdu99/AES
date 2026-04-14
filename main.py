from algo.aes import AES
from algo.mode import ECB, CTR, OFB, CFB, CBC

if __name__ == "__main__":
    with open("./keys/aes_key.txt", "r") as f:
        key = f.read().strip()

    aes = AES(key, mode=128)

    mode = CTR(aes, "12345678abcdef00") # Thay bằng ECB, CTR, OFB, CFB, CBC
    plaintext_path = "./data/aes_plaintext_1.txt"
    encrypted_path = "./data/encrypted_1.bin"
    decrypted_path = "./data/decrypted_1.txt"
    
    mode.encrypt(plaintext_path, encrypted_path)
    mode.decrypt(encrypted_path, decrypted_path)
    print("Hoàn tất!")
