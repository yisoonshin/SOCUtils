"""
Decrypt AES configuration file with RSA private key, then encrypt the AES key + IV with RSA.
"""


import argparse
from cryptoTools import *


def init_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='target file to be decrypted', required=True)
    parser.add_argument('-c', '--aes_conf', help='encrypted AES configuration', required=True)
    parser.add_argument('-k', '--private_key', help='RSA private key .pem file', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = init_argparse()
    print('Input the passphrase for your private key (blank if none)')
    passphrase = getpass("> ").strip()  # get user input for private key passphrase
    if passphrase == '':
        passphrase=None

    privkey = load_rsa_key(args.private_key, passphrase)  # load RSA key from PEM
    plaintext = fullstack_decrypt(args.file, args.aes_conf, privkey)  # decrypt AES key and IV, then decrypt target.

    outfile = args.file.split('.encrypted')[0]
    print(f'[+] Dumping decrypted contents to {outfile}...')

    with open(outfile, 'w') as f:
        f.write(plaintext)
