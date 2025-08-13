// Performs AES encryption/decryption using OpenSSL.
#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>

class CryptoHandler {
public:
    CryptoHandler(const std::string& key, const std::string& iv);
    ~CryptoHandler();
    
    // Encrypt data
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> encrypt(const std::string& data);
    
    // Decrypt data
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encryptedData);
    std::string decryptToString(const std::vector<unsigned char>& encryptedData);
    
    // Utility functions
    static std::string bytesToHex(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);

private:
    EVP_CIPHER_CTX* encryptCtx;
    EVP_CIPHER_CTX* decryptCtx;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
    void initialize();
    void cleanup();
};
