// Performs AES encryption/decryption using OpenSSL.
#include "CryptoHandler.h"
#include "Logger.h"
#include <openssl/err.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

CryptoHandler::CryptoHandler(const std::string& key, const std::string& iv) 
    : encryptCtx(nullptr), decryptCtx(nullptr) {
    
    // Convert hex strings to bytes
    this->key = hexToBytes(key);
    this->iv = hexToBytes(iv);
    
    if (this->key.size() != 32) {
        Logger::Error("Invalid AES key size. Expected 32 bytes (256 bits)");
        throw std::runtime_error("Invalid key size");
    }
    
    if (this->iv.size() != 16) {
        Logger::Error("Invalid AES IV size. Expected 16 bytes (128 bits)");
        throw std::runtime_error("Invalid IV size");
    }
    
    initialize();
}

CryptoHandler::~CryptoHandler() {
    cleanup();
}

void CryptoHandler::initialize() {
    // Initialize encryption context
    encryptCtx = EVP_CIPHER_CTX_new();
    if (!encryptCtx) {
        Logger::Error("Failed to create encryption context");
        throw std::runtime_error("OpenSSL encryption context creation failed");
    }
    
    if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        Logger::Error("Failed to initialize encryption");
        throw std::runtime_error("OpenSSL encryption initialization failed");
    }
    
    // Initialize decryption context
    decryptCtx = EVP_CIPHER_CTX_new();
    if (!decryptCtx) {
        Logger::Error("Failed to create decryption context");
        throw std::runtime_error("OpenSSL decryption context creation failed");
    }
    
    if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        Logger::Error("Failed to initialize decryption");
        throw std::runtime_error("OpenSSL decryption initialization failed");
    }
    
    Logger::Debug("CryptoHandler initialized successfully");
}

void CryptoHandler::cleanup() {
    if (encryptCtx) {
        EVP_CIPHER_CTX_free(encryptCtx);
        encryptCtx = nullptr;
    }
    if (decryptCtx) {
        EVP_CIPHER_CTX_free(decryptCtx);
        decryptCtx = nullptr;
    }
}

std::vector<unsigned char> CryptoHandler::encrypt(const std::vector<unsigned char>& data) {
    if (!encryptCtx) {
        Logger::Error("Encryption context not initialized");
        return {};
    }
    
    std::vector<unsigned char> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    
    if (EVP_EncryptUpdate(encryptCtx, encrypted.data(), &outLen, data.data(), data.size()) != 1) {
        Logger::Error("Encryption failed");
        return {};
    }
    
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(encryptCtx, encrypted.data() + outLen, &finalLen) != 1) {
        Logger::Error("Encryption finalization failed");
        return {};
    }
    
    encrypted.resize(outLen + finalLen);
    return encrypted;
}

std::vector<unsigned char> CryptoHandler::encrypt(const std::string& data) {
    std::vector<unsigned char> dataVec(data.begin(), data.end());
    return encrypt(dataVec);
}

std::vector<unsigned char> CryptoHandler::decrypt(const std::vector<unsigned char>& encryptedData) {
    if (!decryptCtx) {
        Logger::Error("Decryption context not initialized");
        return {};
    }
    
    std::vector<unsigned char> decrypted(encryptedData.size());
    int outLen = 0;
    
    if (EVP_DecryptUpdate(decryptCtx, decrypted.data(), &outLen, encryptedData.data(), encryptedData.size()) != 1) {
        Logger::Error("Decryption failed");
        return {};
    }
    
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(decryptCtx, decrypted.data() + outLen, &finalLen) != 1) {
        Logger::Error("Decryption finalization failed");
        return {};
    }
    
    decrypted.resize(outLen + finalLen);
    return decrypted;
}

std::string CryptoHandler::decryptToString(const std::vector<unsigned char>& encryptedData) {
    auto decrypted = decrypt(encryptedData);
    return std::string(decrypted.begin(), decrypted.end());
}

std::string CryptoHandler::bytesToHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> CryptoHandler::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}
