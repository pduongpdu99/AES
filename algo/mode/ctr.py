import os
from tqdm import tqdm

from algo.file_tools import FileTools
from algo.utils import xor_blocks, increment_ctr


class CTR:
    def __init__(self, aes, nonce=None):
        if type(nonce) is str:
            nonce = bytes.fromhex(nonce)
        self.aes = aes
        self.ctr = ((nonce.hex() or os.urandom(8).hex()) + "0000000000000000")

    def encrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        encrypted = [self.ctr]
        counter = self.ctr

        for block in tqdm(blocks, desc="CTR Encrypt"):
            keystream = self.aes.cipher(counter)
            encrypted.append(xor_blocks(keystream, block))
            counter = increment_ctr(counter)

        FileTools.write_file(outfile, encrypted)

    def decrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        counter = blocks[0]
        decrypted = []

        for block in tqdm(blocks[1:], desc="CTR Decrypt"):
            keystream = self.aes.cipher(counter)
            decrypted.append(xor_blocks(keystream, block))
            counter = increment_ctr(counter)

        FileTools.write_file(outfile, decrypted)
