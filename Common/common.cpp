#include "common.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>

std::string aes_key = "ThisIsASecretKeyThatIs32BytesLong!!"; // 32-byte key for AES-256

void handleErrors() {
    std::cerr << "Error: Failed to initialize OpenSSL." << std::endl;
    exit(EXIT_FAILURE);
}

void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx;
    int len;
    ctx = EVP_CIPHER_CTX_new();
    // Call the method from OpenSSL to create and initialize the context. Then call the handleErrors() method
    if (ctx != EVP_CIPHER_CTX_new()) {
        handleErrors();
    }
    // Call the method from OpenSSL to initialize encryption operation. Then call the handleErrors() method
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)aes_key.c_str(), iv) != true) {
        handleErrors();
    }
    // Call the method from OpenSSL to encrypt plaintext. Then call the handleErrors() method
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.c_str(), plaintext.length()) != true) {
        handleErrors();
    }
    *ciphertext_len = len;
    // Call the method from OpenSSL to finalize encryption. Then call the handleErrors() method
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != true) {
        handleErrors();
    }
    // Add the final length to the total ciphertext length
    *ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void decryptMessage(EVP_CIPHER_CTX* ctx, const unsigned char* encryptedData, int encryptedLen, const unsigned char* aesKey, const unsigned char* iv, unsigned char* decryptedBuffer) {
    // Call the method from OpenSSL to initialize decryption context with AES-256-CBC. Then call handleErrors()
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, iv) != true) {
        handleErrors();
    }

    int decryptedLen;
    // Call the method from OpenSSL to decrypt the encrypted data. Then call handleErrors()
    if (EVP_DecryptUpdate(ctx, decryptedBuffer, &decryptedLen, encryptedData, encryptedLen) != true) {
        handleErrors();
    }
    

    int finalDecryptedLen;
    // Call the method from OpenSSL to finalize decryption. Then call handleErrors()
    if (EVP_DecryptFinal_ex(ctx, decryptedBuffer + decryptedLen, &finalDecryptedLen) != true) {
        handleErrors();
    }

    decryptedLen += finalDecryptedLen;

    decryptedBuffer[decryptedLen] = '\0'; 
}