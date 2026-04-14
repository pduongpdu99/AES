class FileTools:

    @staticmethod
    def read_file(path, block_size=16):
        with open(path, "rb") as f:
            data = f.read()

        # chia block chuẩn
        blocks = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]

            # padding nếu thiếu
            if len(block) < block_size:
                block = block.ljust(block_size, b'\x00')

            blocks.append(block.hex())

        return blocks

    @staticmethod
    def write_file(path, blocks):
        with open(path, "wb") as f:
            for block in blocks:
                f.write(bytes.fromhex(block))
