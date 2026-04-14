import os
from algo.aes import AES
from algo.mode import ECB, CTR, OFB, CFB, CBC

if __name__ == "__main__":
    # 1. Đọc khóa từ file
    try:
        with open("./keys/aes_key.txt", "r") as f:
            key = f.read().strip()
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy tệp tin khóa tại ./keys/aes_key.txt")
        exit()

    # Khởi tạo lõi AES
    aes = AES(key, mode=128)

    # Cấu hình đường dẫn tệp tin
    plaintext_path = "./data/aes_plaintext.txt"
    nonce_fixed = "12345678abcdef0012345678abcdef00"

    modes_to_test = {
        "ECB": ECB(aes),
        "CBC": CBC(aes, iv=nonce_fixed),
        # CTR thường dùng 8 bytes nonce + 8 bytes counter
        "CTR": CTR(aes, nonce=nonce_fixed[:16]),
        "OFB": OFB(aes, iv=nonce_fixed),
        "CFB": CFB(aes, iv=nonce_fixed)
    }

    print(f"{'Mode':<10} | {'Trạng thái':<15}")
    print("-" * 30)

    # 3. Vòng lặp tự động cover tất cả các mode
    for mode_name, mode_obj in modes_to_test.items():
        try:
            # Tạo đường dẫn file riêng biệt cho từng mode để so sánh
            enc_path = f"./data/encrypted_{mode_name}.bin"
            dec_path = f"./data/decrypted_{mode_name}.txt"

            # Thực thi mã hóa
            mode_obj.encrypt(plaintext_path, enc_path)

            # Thực thi giải mã
            mode_obj.decrypt(enc_path, dec_path)

            print(f"{mode_name:<10} | Hoàn tất")
        except Exception as e:
            print(f"{mode_name:<10} | Lỗi: {str(e)}")

    print("-" * 30)
    print("Quá trình thực nghiệm tất cả các chế độ đã hoàn tất!")
