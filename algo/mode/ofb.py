from tqdm import tqdm
from algo.file_tools import FileTools
from algo.utils import generate_random_iv, xor_blocks


class OFB:
    def __init__(self, aes, iv=None):
        self.aes = aes
        self.iv = iv or generate_random_iv()

    def encrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        encrypted = [self.iv]
        feedback = self.iv

        for block in tqdm(blocks, desc="OFB Encrypt"):
            feedback = self.aes.cipher(feedback)
            encrypted.append(xor_blocks(feedback, block))

        FileTools.write_file(outfile, encrypted)

    def decrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        iv = blocks[0]
        decrypted = []
        feedback = iv

        for block in tqdm(blocks[1:], desc="OFB Decrypt"):
            feedback = self.aes.cipher(feedback)
            decrypted.append(xor_blocks(feedback, block))

        FileTools.write_file(outfile, decrypted)
