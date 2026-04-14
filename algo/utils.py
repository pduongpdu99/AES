import os


def random_key_generator(key_length):
    """Tạo key ngẫu nhiên theo độ dài bit, trả về hex string"""
    return os.urandom(key_length // 8).hex()


def generate_random_iv(iv_length=16):
    """Tạo IV ngẫu nhiên (mặc định 16 bytes = 128 bit)"""
    return os.urandom(iv_length).hex()


def pad(block, block_length=16):
    """PKCS7 Padding"""
    bytes_to_pad = block_length - (len(block) // 2)
    padding = format(bytes_to_pad, '02x') * bytes_to_pad
    return block + padding


def unpad(block):
    """Remove PKCS7 Padding"""
    padding_length = int(block[-2:], 16)
    return block[:-padding_length * 2]


def xor_blocks(block1, block2):
    """XOR hai block hex string với độ dài thực tế của block2"""
    b1 = bytes.fromhex(block1)
    b2 = bytes.fromhex(block2)
    return bytes(a ^ b for a, b in zip(b1, b2)).hex()


def increment_ctr(ctr):
    """Tăng counter lên 1 (big-endian)"""
    ctr_int = int.from_bytes(bytes.fromhex(ctr), 'big') + 1
    return ctr_int.to_bytes(16, 'big').hex()


def hardcoded_keys(path, byte_length=16):
    """
    Chuyển đổi danh sách mật khẩu text thành danh sách khóa Hex chuẩn AES.
    :param path: Đường dẫn file chứa mật khẩu (mỗi dòng 1 mật khẩu)
    :param byte_length: 16 (128-bit), 24 (192-bit), 32 (256-bit)
    """
    try:
        with open(path, "r", encoding="latin-1") as f:
            passwords = f.read().splitlines()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file tại {path}")
        return []

    hex_keys = []
    for pwd in passwords:
        if not pwd:
            continue

        # Chuyển text sang bytes
        pwd_bytes = pwd.encode('utf-8')

        if len(pwd_bytes) >= byte_length:
            # Nếu mật khẩu dài hơn, cắt đúng số byte cần thiết
            key_hex = pwd_bytes[:byte_length].hex()
        else:
            # Nếu mật khẩu ngắn hơn, thực hiện Padding (PKCS7) để đủ độ dài
            key_hex = pad(pwd_bytes.hex(), block_length=byte_length)

        hex_keys.append(key_hex)

    return hex_keys


def hex_to_text(hex_str):
    try:
        hex_str = hex_str.replace(" ", "").lower()
        if len(hex_str) % 2 != 0 or not all(c in "0123456789abcdef" for c in hex_str):
            raise ValueError("Invalid hexadecimal string.")
        text = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
        return text
    except Exception as e:
        return f"Error: {e}"


def text_to_hex(text):
    return text.encode('utf-8').hex()


def text_to_bytes(text):
    return text.encode('utf-8')
