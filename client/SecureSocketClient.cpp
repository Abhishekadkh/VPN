// Manages TLS client connection to server.
#include "SecureSocketClient.h"
#include "Logger.h"
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <errno.h>

SecureSocketClient::SecureSocketClient() 
    : ssl(nullptr), ctx(nullptr), sockfd(-1), connected(false) {
    initializeSSL();
}

SecureSocketClient::~SecureSocketClient() {
    disconnect();
    cleanupSSL();
}

void SecureSocketClient::initializeSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        Logger::Error("Failed to create SSL context");
        printSSLErrors();
        throw std::runtime_error("SSL context creation failed");
    }
    
    Logger::Debug("SSL initialized successfully");
}

void SecureSocketClient::cleanupSSL() {
    if (ssl) {
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
    EVP_cleanup();
}

bool SecureSocketClient::setupSSLContext(const std::string& caCertPath, 
                                        const std::string& clientCertPath, 
                                        const std::string& clientKeyPath) {
    // Load CA certificate
    if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) != 1) {
        Logger::Error("Failed to load CA certificate: " + caCertPath);
        printSSLErrors();
        return false;
    }
    
    // Load client certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, clientCertPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        Logger::Error("Failed to load client certificate: " + clientCertPath);
        printSSLErrors();
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, clientKeyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        Logger::Error("Failed to load client private key: " + clientKeyPath);
        printSSLErrors();
        return false;
    }
    
    // Verify private key
    if (SSL_CTX_check_private_key(ctx) != 1) {
        Logger::Error("Private key verification failed");
        printSSLErrors();
        return false;
    }
    
    Logger::Debug("SSL context setup completed");
    return true;
}

bool SecureSocketClient::connect(const std::string& serverIP, int port, 
                                const std::string& caCertPath, 
                                const std::string& clientCertPath, 
                                const std::string& clientKeyPath) {
    // Setup SSL context
    if (!setupSSLContext(caCertPath, clientCertPath, clientKeyPath)) {
        return false;
    }
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        Logger::Error("Failed to create socket");
        return false;
    }
    
    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect to server
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        Logger::Error("Invalid server IP address: " + serverIP);
        close(sockfd);
        sockfd = -1;
        return false;
    }
    
    if (::connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        if (errno != EINPROGRESS) {
            Logger::Error("Failed to connect to server");
            close(sockfd);
            sockfd = -1;
            return false;
        }
    }
    
    Logger::Debug("Socket connected, performing SSL handshake...");
    
    // Create SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        Logger::Error("Failed to create SSL object");
        close(sockfd);
        sockfd = -1;
        return false;
    }
    
    SSL_set_fd(ssl, sockfd);
    
    // Ensure socket is in blocking mode for SSL handshake
    int ssl_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, ssl_flags & ~O_NONBLOCK); // Remove non-blocking flag
    
    // Set a reasonable timeout for the SSL handshake
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10 second timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Perform SSL handshake in blocking mode
    Logger::Debug("Performing SSL handshake...");
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        Logger::Error("SSL handshake failed, error: " + std::to_string(err));
        
        // Provide more detailed error information
        switch(err) {
            case SSL_ERROR_WANT_READ:
                Logger::Error("SSL_ERROR_WANT_READ: Handshake needs more data (should not happen in blocking mode)");
                break;
            case SSL_ERROR_WANT_WRITE:
                Logger::Error("SSL_ERROR_WANT_WRITE: Handshake needs to write data (should not happen in blocking mode)");
                break;
            case SSL_ERROR_ZERO_RETURN:
                Logger::Error("SSL_ERROR_ZERO_RETURN: Connection closed during handshake");
                break;
            case SSL_ERROR_SYSCALL:
                Logger::Error("SSL_ERROR_SYSCALL: System call error during handshake");
                if (errno != 0) {
                    Logger::Error("System error: " + std::string(strerror(errno)));
                }
                break;
            case SSL_ERROR_SSL:
                Logger::Error("SSL_ERROR_SSL: SSL library error during handshake");
                break;
            default:
                Logger::Error("Unknown SSL error during handshake: " + std::to_string(err));
                break;
        }
        
        printSSLErrors();
        SSL_free(ssl);
        ssl = nullptr;
        close(sockfd);
        sockfd = -1;
        return false;
    }
    
    Logger::Debug("SSL handshake completed successfully");
    
    // Verify server certificate (optional for now)
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        Logger::Warning("Server certificate verification failed: " + std::to_string(verify_result));
        // Don't fail the connection for now, just warn
    } else {
        Logger::Debug("Server certificate verification passed");
    }
    
    connected = true;
    Logger::Info("Successfully connected to server via TLS");
    return true;
}

void SecureSocketClient::disconnect() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    connected = false;
    Logger::Debug("Disconnected from server");
}

bool SecureSocketClient::isConnected() const {
    return connected && ssl && sockfd >= 0;
}

int SecureSocketClient::send(const std::vector<unsigned char>& data) {
    if (!isConnected()) {
        Logger::Error("Not connected to server");
        return -1;
    }
    
    int ret = SSL_write(ssl, data.data(), data.size());
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            Logger::Error("SSL write failed");
            printSSLErrors();
            return -1;
        }
        return 0; // Would block
    }
    
    return ret;
}

int SecureSocketClient::send(const std::string& data) {
    std::vector<unsigned char> dataVec(data.begin(), data.end());
    return send(dataVec);
}

int SecureSocketClient::receive(std::vector<unsigned char>& data) {
    if (!isConnected()) {
        Logger::Error("Not connected to server");
        return -1;
    }
    
    data.resize(4096); // Buffer size
    int ret = SSL_read(ssl, data.data(), data.size());
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN) {
            Logger::Debug("Server closed connection");
            return -2; // Special return code for connection closed
        } else if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            Logger::Error("SSL read failed");
            printSSLErrors();
            return -1;
        }
        return 0; // Would block (no data available)
    }
    
    data.resize(ret);
    return ret;
}

int SecureSocketClient::receive(std::string& data) {
    std::vector<unsigned char> dataVec;
    int ret = receive(dataVec);
    if (ret > 0) {
        data = std::string(dataVec.begin(), dataVec.end());
    }
    return ret;
}

int SecureSocketClient::getSocketFd() const {
    return sockfd;
}

void SecureSocketClient::printSSLErrors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        Logger::Debug("SSL Error: " + std::string(err_buf));
    }
}
