"""
Encrypt target file using AES CBC, then encrypt the AES key + IV with RSA.
"""


import argparse
from os.path import exists
from cryptoTools import *


def init_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='target file to be encrypted', required=True)
    parser.add_argument('-k', '--public_key', help='RSA public key .pem file if you have one already')
    return parser.parse_args()


def rsa_keygen_prompt():
    print('Please choose a project name for your RSA keys:')
    rsa_project = input("> ")  # get user input
    while exists(f'{rsa_project}.pem'):  # if a similar name already exists, prompt for another
        print('There already exists a set of keys with that name, please choose another:')
        rsa_project = input("> ")
    passphrase = choose_passphrase()
    keypair = rsa_keygen(4096, priv_key_pass=passphrase)
    write_rsa_keys(rsa_project, keypair)
    return RSA.import_key(keypair[0])  # we only need the public key for encryption


if __name__ == "__main__":
    args = init_argparse()
    # load or generate public key
    if not args.public_key:  # if no existing key is given, generate one.
        pub_key = rsa_keygen_prompt()
    else:  # otherwise, load the key from file
        pub_key = load_rsa_key(args.public_key)

    aes_conf = aes_cbc_keygen(16)  # generate a key and IV for AES-256 CBC

    outfile = f'{args.file}.encrypted'
    dupe_counter = 2
    while exists(outfile):  # if an encrypted version already exists, write duplicate w/indicator
        outfile = f'{args.file}.encrypted({dupe_counter})'
        dupe_counter += 1

    with open(args.file, 'rb') as target_file:
        plaintext = target_file.read().strip()
        ciphertext = aes_encrypt(plaintext, aes_conf)  # perform the AES encryption
        with open(outfile, 'wb') as dest_file:
            print(f'[+] Writing ciphertext to {outfile}...remove the plaintext copy later.')
            dest_file.write(ciphertext)

    aes_tuple_export(args.file, aes_conf, pub_key)  # write the RSA-encrypted key and IV pair for this AES cipher
