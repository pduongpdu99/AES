import os
from algo.utils import xor_blocks
from algo.file_tools import FileTools


class GCM:
    def __init__(self, aes, nonce=None, tag_length=16):
        self.aes = aes
        self.tag_length = tag_length

        if nonce is None:
            # 96-bit nonce khuyến nghị
            self.nonce = os.urandom(12).hex()
        else:
            self.nonce = nonce if isinstance(nonce, str) else nonce.hex()

        if len(self.nonce) != 24:
            raise ValueError("Nonce phải là 12 bytes (24 ký tự hex)")

    # ====================== GHASH CORE ======================
    def _mul(self, x, y):
        """Nhân trong trường GF(2^128) với irreducible polynomial x^128 + x^7 + x^2 + x + 1"""
        res = 0
        for i in range(128):
            if (y >> (127 - i)) & 1:
                res ^= x
            hi_bit = (x >> 127) & 1
            x = (x << 1) & ((1 << 128) - 1)
            if hi_bit:
                x ^= 0x87
        return res

    def _ghash(self, h, aad_hex, ct_hex):
        """Tính GHASH(H, AAD, C)"""
        def block_to_int(b):
            return int(b.ljust(32, '0'), 16)

        y = 0
        h_int = int(h, 16)

        # Process AAD
        for i in range(0, len(aad_hex), 32):
            block = aad_hex[i:i+32]
            y = self._mul(y ^ block_to_int(block), h_int)

        # Process Ciphertext
        for i in range(0, len(ct_hex), 32):
            block = ct_hex[i:i+32]
            y = self._mul(y ^ block_to_int(block), h_int)

        # Length block: len(AAD) || len(C)  (in bits, big-endian, 64-bit each)
        len_aad_bits = len(aad_hex) * 4
        len_ct_bits = len(ct_hex) * 4
        len_block = (len_aad_bits.to_bytes(8, 'big') +
                     len_ct_bits.to_bytes(8, 'big')).hex()

        y = self._mul(y ^ int(len_block, 16), h_int)

        return f"{y:032x}"

    def encrypt(self, infile, outfile, aad=b""):
        # 1. Đọc dữ liệu thô từ file
        with open(infile, "rb") as f:
            data = f.read()

        # --- CẬP NHẬT: Chuẩn hóa AAD sang Hex ---
        # Nếu là string (ví dụ: "UserID:123"), encode sang bytes rồi chuyển hex
        if isinstance(aad, str):
            try:
                # Thử xem có phải chuỗi hex sẵn không
                int(aad, 16)
                aad_hex = aad
            except ValueError:
                # Nếu không phải hex, thì đây là văn bản thuần -> encode utf-8
                aad_hex = aad.encode('utf-8').hex()
        elif isinstance(aad, (bytes, bytearray)):
            aad_hex = aad.hex()
        else:
            aad_hex = ""

        # 2. Khởi tạo Counter (J0 = Nonce || 00000001)
        # Quá trình mã hóa thực tế bắt đầu từ J0 + 1 (tức là đuôi 00000002)
        nonce_bytes = bytes.fromhex(self.nonce)
        counter_int = int.from_bytes(nonce_bytes + b'\x00\x00\x00\x02', 'big')

        ciphertext_blocks = []

        # 3. CTR Mode Encryption
        for i in range(0, len(data), 16):
            plain_hex = data[i:i+16].hex()
            # Tạo keystream bằng cách mã hóa giá trị counter
            keystream = self.aes.cipher(counter_int.to_bytes(16, 'big').hex())

            # XOR keystream với plaintext
            cipher_block = xor_blocks(keystream, plain_hex)

            # Giữ đúng độ dài cho khối cuối (nếu lẻ)
            actual_len = len(data[i:i+16]) * 2
            ciphertext_blocks.append(cipher_block[:actual_len])

            counter_int += 1

        # 4. Tính toán Authentication Tag
        # h = E(K, 0^128)
        h = self.aes.cipher("0" * 32)
        ct_hex_full = "".join(ciphertext_blocks)

        # Gọi hàm GHASH với AAD và Ciphertext đã chuẩn hóa
        ghash_res = self._ghash(h, aad_hex, ct_hex_full)

        # Tạo mặt nạ cho Tag bằng E(K, J0) - đuôi 00000001
        e0 = self.aes.cipher(self.nonce + "00000001")
        tag = xor_blocks(ghash_res, e0)[:self.tag_length * 2]

        # 5. Ghi file theo cấu trúc chuẩn: Nonce(12 bytes) + Ciphertext + Tag(16 bytes)
        with open(outfile, "wb") as f:
            f.write(bytes.fromhex(self.nonce))
            for block in ciphertext_blocks:
                f.write(bytes.fromhex(block))
            f.write(bytes.fromhex(tag))

        print("Encrypt GCM thành công!")
        return self.nonce, ct_hex_full, tag

    def decrypt(self, infile, outfile, aad=b""):
        # 1. Đọc toàn bộ file nhị phân
        with open(infile, "rb") as f:
            all_data = f.read()

        if len(all_data) < 28:
            raise ValueError("File dữ liệu GCM không hợp lệ (quá ngắn)")

        # 2. Bóc tách chính xác vị trí byte
        nonce_hex = all_data[:12].hex()
        tag_received = all_data[-16:].hex()
        ciphertext_bytes = all_data[12:-16]

        ct_hex_full = ciphertext_bytes.hex()
        aad_hex = aad.hex() if isinstance(aad, (bytes, bytearray)) else aad

        # 3. Xác thực tính toàn vẹn (Authentication)
        h = self.aes.cipher("0" * 32)
        ghash_res = self._ghash(h, aad_hex, ct_hex_full)
        e0 = self.aes.cipher(nonce_hex + "00000001")
        expected_tag = xor_blocks(ghash_res, e0)[:self.tag_length * 2]

        if tag_received != expected_tag:
            print(
                f"Authentication failed!\nReceived: {tag_received}\nExpected: {expected_tag}")
            raise ValueError("Dữ liệu đã bị thay đổi hoặc sai Key.")

        # 4. Giải mã CTR (bắt đầu từ counter 2)
        counter_int = int.from_bytes(bytes.fromhex(
            nonce_hex) + b'\x00\x00\x00\x02', 'big')

        decrypted_blocks = []
        for i in range(0, len(ciphertext_bytes), 16):
            ct_hex_block = ciphertext_bytes[i:i+16].hex()
            keystream = self.aes.cipher(counter_int.to_bytes(16, 'big').hex())

            plain_hex = xor_blocks(keystream, ct_hex_block)
            decrypted_blocks.append(plain_hex[:len(ct_hex_block)])
            counter_int += 1

        # 5. Ghi file Plaintext
        FileTools.write_file(outfile, decrypted_blocks)
        print("Giải mã và xác thực GCM thành công!")
        return "".join(decrypted_blocks)

    @staticmethod
    def _constant_time_compare(a, b):
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        return result == 0
