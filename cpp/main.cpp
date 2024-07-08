#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

const int AES_KEY_LENGTH = 256;
const int SALT_LENGTH = 16;
const int KEY_LENGTH = 32; // 256 bits
const int IV_LENGTH = 16;  // 128 bits

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void deriveKey(const std::string& passphrase, unsigned char* salt, unsigned char* key) {
    if (!PKCS5_PBKDF2_HMAC_SHA1(passphrase.c_str(), passphrase.length(), salt, SALT_LENGTH, 10000, KEY_LENGTH, key)) {
        handleErrors();
    }
}

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& passphrase) {
    // Generate random salt
    unsigned char salt[SALT_LENGTH];
    if (!RAND_bytes(salt, sizeof(salt))) {
        handleErrors();
    }

    // Derive key from passphrase and salt
    unsigned char key[KEY_LENGTH];
    deriveKey(passphrase, salt, key);

    // Generate random IV
    unsigned char iv[IV_LENGTH];
    if (!RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }

    // Read input file
    std::ifstream ifs(inputFile, std::ios::binary);
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    ifs.close();

    // Encrypt data
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> ciphertext(buffer.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buffer.data(), buffer.size())) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Write salt, iv, and ciphertext to output file
    std::ofstream ofs(outputFile, std::ios::binary);
    ofs.write(reinterpret_cast<char*>(salt), SALT_LENGTH);
    ofs.write(reinterpret_cast<char*>(iv), IV_LENGTH);
    ofs.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    ofs.close();
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& passphrase) {
    // Read salt and iv from input file
    std::ifstream ifs(inputFile, std::ios::binary);
    unsigned char salt[SALT_LENGTH];
    unsigned char iv[IV_LENGTH];
    ifs.read(reinterpret_cast<char*>(salt), SALT_LENGTH);
    ifs.read(reinterpret_cast<char*>(iv), IV_LENGTH);

    // Derive key from passphrase and salt
    unsigned char key[KEY_LENGTH];
    deriveKey(passphrase, salt, key);

    // Read ciphertext from input file
    std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    ifs.close();

    // Decrypt data
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Write plaintext to output file
    std::ofstream ofs(outputFile, std::ios::binary);
    ofs.write(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    ofs.close();
}

int main() {
    std::string passphrase;
    std::cout << "Enter passphrase: ";
    std::getline(std::cin, passphrase);

    encryptFile("input.txt", "encrypted.bin", passphrase);
    decryptFile("encrypted.bin", "decrypted.txt", passphrase);

    std::cout << "Encryption and decryption completed successfully.\n";
    return 0;
}