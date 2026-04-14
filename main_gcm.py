import os
import time
from algo.aes import AES
from algo.mode.gcm import GCM


def run_gcm_experiment():
    # 1. Khởi tạo cấu hình
    try:
        with open("./keys/aes_key.txt", "r") as f:
            key = f.read().strip()
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file khóa.")
        return

    aes = AES(key, mode=128)
    gcm = GCM(aes)

    plaintext_path = "./data/aes_plaintext.txt"
    encrypted_path = "./data/encrypted_gcm.bin"
    decrypted_path = "./data/decrypted_gcm.txt"

    print(f"{'--- THỰC NGHIỆM CHẾ ĐỘ AES-GCM ---':^50}")

    # CASE 1: Quy trình mã hóa và giải mã chuẩn (Standard Flow)
    print("\n[Case 1] Quy trình chuẩn:")
    start_time = time.time()
    nonce, ct, tag = gcm.encrypt(plaintext_path, encrypted_path)
    end_time = time.time()

    print(f" - Mã hóa thành công trong: {end_time - start_time:.4f}s")
    print(f" - Nonce (12 bytes): {nonce}")
    print(f" - Tag xác thực: {tag}")

    try:
        gcm.decrypt(encrypted_path, decrypted_path)
        print(" - Giải mã và xác thực thành công!")
    except ValueError as e:
        print(f" - Giải mã thất bại: {e}")

    # CASE 2: Kiểm tra tính toàn vẹn (Integrity Check - Tấn công Bit-flipping)
    print("\n[Case 2] Kiểm tra tính toàn vẹn (Tấn công thay đổi bản mã):")
    # Đọc bản mã vừa ghi, sửa đổi 1 byte cuối cùng
    with open(encrypted_path, "rb") as f:
        data = bytearray(f.read())

    # Sửa đổi bit cuối cùng của bản mã (Ciphertext nằm sau Nonce)
    data[-1] ^= 0x01

    modified_path = "./data/encrypted_gcm_modified.bin"
    with open(modified_path, "wb") as f:
        f.write(data)

    try:
        print(" - Đang thử giải mã bản mã đã bị sửa đổi...")
        gcm.decrypt(modified_path, "./data/decrypted_fail.txt")
    except ValueError:
        print(
            " - KẾT QUẢ: GCM phát hiện dữ liệu bị thay đổi (Tag mismatch). Từ chối giải mã.")

    # CASE 3: Thử nghiệm với dữ liệu bổ sung (AAD - Additional Authenticated Data)
    # GCM cho phép xác thực thông tin không cần mã hóa (như Header của gói tin)
    print("\n[Case 3] Xác thực dữ liệu bổ sung (AAD):")
    aad = "UserID:12345;Timestamp:2026-04-12"
    nonce_aad, ct_aad, tag_aad = gcm.encrypt(
        plaintext_path, "./data/enc_aad.bin", aad=aad)
    print(f" - Mã hóa kèm AAD thành công. Tag: {tag_aad}")

    try:
        # Giải mã với đúng AAD
        gcm.decrypt("./data/enc_aad.bin", "./data/dec_aad.txt", aad=aad)
        print(" - Giải mã với AAD chính xác: Thành công.")
    except ValueError:
        print(" - Giải mã với AAD chính xác: Thất bại.")


if __name__ == "__main__":
    run_gcm_experiment()
