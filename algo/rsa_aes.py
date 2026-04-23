import json
import secrets
import hashlib
from algo.rsa import RSA
from algo.aes import AES


class HybridCryptosystem:

    def __init__(self):
        self.sender_rsa = RSA(512)
        self.receiver_rsa = RSA(512)

    def setup(self):
        self.sender_rsa.generate_keys()
        self.receiver_rsa.generate_keys()

    def generate_aes_key(self):
        return secrets.token_hex(16)

    def pad(self, data):
        p = 16-(len(data) % 16)
        return data+bytes([p])*p

    def unpad(self, data):
        return data[:-data[-1]]

    def sign_file(self, path):

        data = open(
            path,
            "rb"
        ).read()

        h = int(
            hashlib.sha256(
                data
            ).hexdigest(),
            16
        )

        d, n = self.sender_rsa.private_key

        return pow(
            h,
            d,
            n
        )

    def verify_file(
        self,
        path,
        sig
    ):
        data = open(
            path,
            "rb"
        ).read()

        h = int(
            hashlib.sha256(
                data
            ).hexdigest(),
            16
        )

        e, n = self.sender_rsa.public_key

        return pow(
            sig,
            e,
            n
        ) == h

    def encrypt_session_key(
        self,
        key
    ):
        return self.receiver_rsa.encrypt(
            key
        )

    def decrypt_session_key(
        self,
        enc
    ):
        return self.receiver_rsa.decrypt(
            enc
        )

    def encrypt_file(
        self,
        path,
        key
    ):

        aes = AES(key)

        data = open(
            path,
            "rb"
        ).read()

        data = self.pad(data)

        blocks = []

        for i in range(
            0,
            len(data),
            16
        ):

            block = data[
                i:i+16
            ].hex()

            blocks.append(
                aes.cipher(
                    block
                )
            )

        return blocks

    def decrypt_file(
        self,
        blocks,
        key,
        output
    ):

        aes = AES(key)

        recovered = b''

        for b in blocks:
            p = aes.decipher(b)

            recovered += bytes.fromhex(
                p
            )

        recovered = self.unpad(
            recovered
        )

        with open(
            output,
            "wb"
        ) as f:
            f.write(
                recovered
            )

    def send_secure_file(
        self,
        path,
        package_file="package.json"
    ):

        aes_key = self.generate_aes_key()

        package = {

            "encrypted_key":
                str(
                    self.encrypt_session_key(
                        aes_key
                    )
                ),

            "cipher_blocks":
                self.encrypt_file(
                    path,
                    aes_key
                ),

            "signature":
                str(
                    self.sign_file(
                        path
                    )
                )
        }

        json.dump(
            package,
            open(
                package_file,
                "w"
            ),
            indent=2
        )

    def receive_secure_file(
        self,
        package_file,
        output_file
    ):

        package = json.load(
            open(package_file)
        )

        aes_key = self.decrypt_session_key(
            int(
                package[
                    "encrypted_key"
                ]
            )
        )

        self.decrypt_file(
            package[
                "cipher_blocks"
            ],
            aes_key,
            output_file
        )

        return self.verify_file(
            output_file,
            int(
                package[
                    "signature"
                ]
            )
        )
