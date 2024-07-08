import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from file_operations import read_file, write_file
from key_protection import protect_key, retrieve_key

AES_KEY_SIZE = 32  # AES-256

def encrypt_file(file_path, passphrase):
    # Generate a random file encryption key
    file_key = get_random_bytes(AES_KEY_SIZE)

    # Read the plaintext file
    plaintext = read_file(file_path)

    # Encrypt the file
    cipher = AES.new(file_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write the encrypted file
    enc_file_path = file_path + '.enc'
    write_file(enc_file_path, cipher.nonce + tag + ciphertext)

    # Protect and store the file encryption key
    protect_key(file_path, file_key, passphrase)
    return True

def decrypt_file(file_path, passphrase):
    # Retrieve and decrypt the file encryption key
    file_key = retrieve_key(file_path, passphrase)

    # Read the encrypted file
    enc_file_path = file_path + '.enc'
    enc_data = read_file(enc_file_path)
    nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]

    # Decrypt the file
    cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted file
    dec_file_path = file_path + '.dec'
    write_file(dec_file_path, plaintext)
    return True
