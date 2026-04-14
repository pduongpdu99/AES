from tqdm import tqdm

from algo.file_tools import FileTools
from algo.utils import generate_random_iv, xor_blocks


class CFB:
    def __init__(self, aes, iv=None):
        self.aes = aes
        self.iv = iv or generate_random_iv()

    def encrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        encrypted = [self.iv]
        feedback = self.iv

        for block in tqdm(blocks, desc="CFB Encrypt"):
            cipher_block = self.aes.cipher(feedback)
            encrypted_block = xor_blocks(cipher_block, block)
            encrypted.append(encrypted_block)
            feedback = encrypted_block

        FileTools.write_file(outfile, encrypted)

    def decrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        iv = blocks[0]
        decrypted = []
        feedback = iv

        for block in tqdm(blocks[1:], desc="CFB Decrypt"):
            cipher_block = self.aes.cipher(feedback)
            plain_block = xor_blocks(cipher_block, block)
            decrypted.append(plain_block)
            feedback = block

        FileTools.write_file(outfile, decrypted)
