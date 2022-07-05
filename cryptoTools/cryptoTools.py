"""
Collection of cryptography/authentication tools for securing sensitive information like API keys
"""


from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from getpass import getpass


def choose_passphrase():
    pass1 = getpass('Please enter a passphrase: ')
    pass2 = getpass('Please enter it again for verification: ')
    while pass1 != pass2:
        print('Those passphrases did not match. Please try again.')
        pass1 = getpass('Please enter a passphrase: ')
        pass2 = getpass('Please enter it again for verification: ')
    print('[+] Passphrase saved.')
    if pass1.strip():
        return pass1
    else:
        return None

def pad(data):
    """Appends null bytes to end of data for whole 16 byte blocks expected for AES CBC."""
    if type(data) == str:
        data = data.encode()  # convert to bytes

    block_size = 16  # expected for AES CBC
    remainder = len(data) % block_size
    padding = (block_size - remainder) * b'\x00'  # null bytes required to fill out expected block size
    return b''.join([data, padding])  # concat pad to end of data


def unpad(data):
    """Strips padding from decrypted ciphertext."""
    return data.rstrip(b'\x00')  # removes trailing null byte padding


def aes_cbc_keygen(block_size):
    """Generate random key and initialization vector in the size of the expected block."""
    print('[+] Generating key and IV...')
    key = get_random_bytes(block_size)
    iv = get_random_bytes(block_size)
    return key, iv


def create_aes_cipher(key_iv_tuple):
    """Using tuple from aes_cbc_keygen, create a cipher for encrypting/decrypting."""
    return AES.new(key_iv_tuple[0], AES.MODE_CBC, key_iv_tuple[1])


def aes_encrypt(plaintext, key_iv_tuple):
    """Encrypt plaintext using key & IV tuple provided, and convert to Base64."""
    cipher = create_aes_cipher(key_iv_tuple)
    ciphertext = cipher.encrypt(pad(plaintext))
    return b64encode(ciphertext)


def aes_decrypt(ciphertext, key_iv_tuple):
    """Decrypt base64-encoded ciphertext using key & IV tuple provided."""
    cipher = create_aes_cipher(key_iv_tuple)
    plaintext = cipher.decrypt(b64decode(ciphertext))
    return unpad(plaintext)


def rsa_keygen(blocksize=4096, priv_key_pass=None):
    """Generate a keypair and return them as a tuple"""
    print('[+] Generating keypair...this could take a while depending on the amount of bits')
    keypair = RSA.generate(blocksize)
    pubkey = keypair.publickey().exportKey()
    privkey = keypair.exportKey(passphrase=priv_key_pass)  # For extra security, protect private key w/passphrase
    return pubkey, privkey


def write_rsa_keys(project_name, keypair):
    """Write public and private keys from rsa_keygen to PEM files."""
    print(f'[+] Generating keypair for project "{project_name}"...')
    public, private = keypair

    with open(f'{project_name}_pub.pem', 'wb') as f:
        f.write(public)
    print(f'[+] Public key saved: {project_name}_pub.pem')

    with open(f'{project_name}.pem', 'wb') as f:
        f.write(private)
    print(f'[+] Private key saved: {project_name}.pem')
    print('Please move the private key to a safe spot and save the passphrase for future reference.\n')


def load_rsa_key(infile, priv_key_pass=None):
    """Import key from PEM file and return RsaKey object."""
    with open(infile, 'rb') as f:
        key = f.read()
    return RSA.import_key(key, passphrase=priv_key_pass)


def rsa_encrypt(plaintext, key):
    """Using imported RsaKey object, encrypt plaintext and encode as base64."""
    cipher = PKCS1_OAEP.new(key) # generate new cipher object
    ciphertext = cipher.encrypt(plaintext)
    return b64encode(ciphertext) # encode w/base64 to stay within ASCII characterset


def rsa_decrypt(ciphertext, key):
    """Using imported RsaKey object, decode then decrypt base64-encoded ciphertext."""
    cipher = PKCS1_OAEP.new(key) # generate new cipher object
    decoded = b64decode(ciphertext) # undo layer of b64 encoding from encryption step
    return cipher.decrypt(decoded)


def aes_tuple_export(target_file, key_iv_tuple, pubkey, delimiter=b'1337h4x0r'):
    """Write key & IV to file and delimit values using unique byte string."""
    print(f'[+] Writing AES config to {target_file}.conf...')
    with open(f'{target_file}.conf', 'wb') as f:
        data = b64encode(b''.join(
            [key_iv_tuple[0],
             delimiter, # join items w/delimiter and encode w/base64 to stay within ASCII characterset
             key_iv_tuple[1]]))
        f.write(rsa_encrypt(data, pubkey)) # RSA encrypt the b64-encoded string


def aes_tuple_import(infile, privkey, delimiter=b'1337h4x0r'):
    """Read encrypted and b64-encoded key & IV file and parse back into tuple."""
    print(f'[+] Importing AES config from {infile}...')
    with open(infile, 'rb') as f:
        cipher_data = f.read()
    plain_data = b64decode(rsa_decrypt(cipher_data, privkey)) # undo RSA encryption and b64 encoding
    return plain_data.split(delimiter) # split values based on delimiter


def fullstack_decrypt(target, aes_conf, privkey):
    """Decrypt AES conf with private key into memory, then decrypt AES ciphertext."""
    key_iv_tuple = aes_tuple_import(aes_conf, privkey) # obtain the encrypted key and IV
    print(f'[+] Decrypting contents of {target}...')
    with open(target, 'rb') as f:
        ciphertext = f.read()
    return aes_decrypt(ciphertext, key_iv_tuple).decode() # decrypt and return as string (not bytes)
