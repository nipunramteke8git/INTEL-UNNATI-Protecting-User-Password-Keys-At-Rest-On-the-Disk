from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from file_operations import write_file, read_file

SALT_SIZE = 16
AES_KEY_SIZE = 32  # AES-256
ITERATIONS = 100000

def protect_key(file_path, file_key, passphrase):
    salt = get_random_bytes(SALT_SIZE)
    derived_key = PBKDF2(passphrase, salt, dkLen=AES_KEY_SIZE, count=ITERATIONS)


    cipher = AES.new(derived_key, AES.MODE_GCM)
    enc_file_key, tag = cipher.encrypt_and_digest(file_key)

    # Write the protected key to a file
    key_file_path = file_path + '.key'
    write_file(key_file_path, salt + cipher.nonce + tag + enc_file_key)

def retrieve_key(file_path, passphrase):
    # Read the protected key from the file
    key_file_path = file_path + '.key'
    key_data = read_file(key_file_path)
    salt, nonce, tag, enc_file_key = key_data[:SALT_SIZE], key_data[SALT_SIZE:SALT_SIZE+16], key_data[SALT_SIZE+16:SALT_SIZE+32], key_data[SALT_SIZE+32:]

    # Generate derived key
    derived_key = PBKDF2(passphrase, salt, dkLen=AES_KEY_SIZE, count=ITERATIONS)

    # Decrypt the file encryption key
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    file_key = cipher.decrypt_and_verify(enc_file_key, tag)

    return file_key
