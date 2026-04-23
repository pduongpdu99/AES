from algo.rsa_aes import HybridCryptosystem

hybrid = HybridCryptosystem()

hybrid.setup()

hybrid.send_secure_file(
    path="./data/rsa_plaintext.txt",
    package_file='./meta/package.json'
)

ok = hybrid.receive_secure_file(
    "./meta/package.json",
    "./meta/recovered.txt"
)

print(ok)
