from tqdm import tqdm

from algo.file_tools import FileTools
from algo.utils import generate_random_iv, pad, unpad, xor_blocks


class CBC:
    def __init__(self, aes, iv=None):
        self.aes = aes
        self.iv = iv or generate_random_iv()

    def encrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        if len(blocks[-1]) < 32:
            blocks[-1] = pad(blocks[-1])

        encrypted = [self.iv]
        prev = self.iv

        for block in tqdm(blocks, desc="CBC Encrypt"):
            xored = xor_blocks(prev, block)
            cipher_block = self.aes.cipher(xored)
            encrypted.append(cipher_block)
            prev = cipher_block

        FileTools.write_file(outfile, encrypted)

    def decrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        iv = blocks[0]
        decrypted = []
        prev = iv

        for block in tqdm(blocks[1:], desc="CBC Decrypt"):
            plain = self.aes.decipher(block)
            decrypted.append(xor_blocks(prev, plain))
            prev = block

        decrypted[-1] = unpad(decrypted[-1])
        FileTools.write_file(outfile, decrypted)
