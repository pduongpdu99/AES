from tqdm import tqdm
from algo.utils import pad, unpad
from algo.file_tools import FileTools


class ECB:
    def __init__(self, aes):
        self.aes = aes

    def encrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        if len(blocks[-1]) < 32:
            blocks[-1] = pad(blocks[-1])

        encrypted = []
        for block in tqdm(blocks, desc="ECB Encrypt"):
            encrypted.append(self.aes.cipher(block))

        FileTools.write_file(outfile, encrypted)

    def decrypt(self, infile, outfile):
        blocks = FileTools.read_file(infile)
        decrypted = []
        for block in tqdm(blocks, desc="ECB Decrypt"):
            decrypted.append(self.aes.decipher(block))

        decrypted[-1] = unpad(decrypted[-1])
        FileTools.write_file(outfile, decrypted)
