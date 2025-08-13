// TLS listener for encrypted sessions.
#include "SecureSocketServer.h"
#include "Logger.h"
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <stdexcept>
#include <errno.h>

SecureSocketServer::SecureSocketServer() 
    : ctx(nullptr), serverFd(-1), running(false) {
    initializeSSL();
}

SecureSocketServer::~SecureSocketServer() {
    stop();
    cleanupSSL();
}

void SecureSocketServer::initializeSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        Logger::Error("Failed to create SSL context");
        printSSLErrors();
        throw std::runtime_error("SSL context creation failed");
    }
    
    Logger::Debug("SSL initialized successfully");
}

void SecureSocketServer::cleanupSSL() {
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
    EVP_cleanup();
}

bool SecureSocketServer::setupSSLContext(const std::string& caCertPath, 
                                        const std::string& serverCertPath, 
                                        const std::string& serverKeyPath) {
    // Load CA certificate for client verification
    if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) != 1) {
        Logger::Error("Failed to load CA certificate: " + caCertPath);
        printSSLErrors();
        return false;
    }
    
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, serverCertPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        Logger::Error("Failed to load server certificate: " + serverCertPath);
        printSSLErrors();
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, serverKeyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        Logger::Error("Failed to load server private key: " + serverKeyPath);
        printSSLErrors();
        return false;
    }
    
    // Verify private key
    if (SSL_CTX_check_private_key(ctx) != 1) {
        Logger::Error("Private key verification failed");
        printSSLErrors();
        return false;
    }
    
    // Set client certificate verification (make it optional for initial connection)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    
    Logger::Debug("SSL context setup completed");
    return true;
}

bool SecureSocketServer::start(int port, const std::string& caCertPath, 
                              const std::string& serverCertPath, 
                              const std::string& serverKeyPath) {
    // Setup SSL context
    if (!setupSSLContext(caCertPath, serverCertPath, serverKeyPath)) {
        return false;
    }
    
    // Create server socket
    serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        Logger::Error("Failed to create server socket");
        return false;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Set non-blocking
    int flags = fcntl(serverFd, F_GETFL, 0);
    fcntl(serverFd, F_SETFL, flags | O_NONBLOCK);
    
    // Bind socket
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(serverFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        Logger::Error("Failed to bind server socket to port " + std::to_string(port));
        close(serverFd);
        serverFd = -1;
        return false;
    }
    
    // Listen for connections
    if (listen(serverFd, 10) < 0) {
        Logger::Error("Failed to listen on server socket");
        close(serverFd);
        serverFd = -1;
        return false;
    }
    
    running = true;
    Logger::Info("Server started and listening on port " + std::to_string(port));
    return true;
}

void SecureSocketServer::stop() {
    running = false;
    if (serverFd >= 0) {
        close(serverFd);
        serverFd = -1;
    }
    Logger::Info("Server stopped");
}

bool SecureSocketServer::isRunning() const {
    return running && serverFd >= 0;
}

bool SecureSocketServer::acceptClient(SSL*& clientSSL, int& clientFd) {
    if (!isRunning()) {
        return false;
    }
    
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    
    clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (clientFd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            Logger::Error("Failed to accept client connection");
        }
        return false;
    }
    
    Logger::Debug("New client connection accepted, performing SSL handshake...");
    
    // Create SSL connection
    clientSSL = SSL_new(ctx);
    if (!clientSSL) {
        Logger::Error("Failed to create SSL object for client");
        close(clientFd);
        clientFd = -1;
        return false;
    }
    
    SSL_set_fd(clientSSL, clientFd);
    
    // Ensure socket is in blocking mode for SSL handshake
    int ssl_flags = fcntl(clientFd, F_GETFL, 0);
    fcntl(clientFd, F_SETFL, ssl_flags & ~O_NONBLOCK); // Remove non-blocking flag
    
    // Set a reasonable timeout for the SSL handshake
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10 second timeout
    timeout.tv_usec = 0;
    setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Perform SSL handshake in blocking mode
    Logger::Debug("Performing SSL handshake...");
    int ret = SSL_accept(clientSSL);
    if (ret != 1) {
        int err = SSL_get_error(clientSSL, ret);
        Logger::Error("SSL handshake with client failed, error: " + std::to_string(err));
        
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
        SSL_free(clientSSL);
        clientSSL = nullptr;
        close(clientFd);
        clientFd = -1;
        return false;
    }
    
    Logger::Debug("SSL handshake completed successfully");
    
    // Now set client socket to non-blocking for data transfer
    int flags = fcntl(clientFd, F_GETFL, 0);
    fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
    
    // Verify client certificate (optional for now)
    long verify_result = SSL_get_verify_result(clientSSL);
    if (verify_result != X509_V_OK) {
        Logger::Warning("Client certificate verification failed: " + std::to_string(verify_result));
        // Don't fail the connection for now, just warn
        // SSL_free(clientSSL);
        // clientSSL = nullptr;
        // close(clientFd);
        // clientFd = -1;
        // return false;
    } else {
        Logger::Debug("Client certificate verification passed");
    }
    
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    Logger::Info("Client connected from " + std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port)));
    
    return true;
}

void SecureSocketServer::closeClient(SSL* clientSSL, int clientFd) {
    if (clientSSL) {
        SSL_shutdown(clientSSL);
        SSL_free(clientSSL);
    }
    if (clientFd >= 0) {
        close(clientFd);
    }
    Logger::Debug("Client connection closed");
}

int SecureSocketServer::send(SSL* ssl, const std::vector<unsigned char>& data) {
    if (!ssl) {
        Logger::Error("Invalid SSL object for sending");
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

int SecureSocketServer::send(SSL* ssl, const std::string& data) {
    std::vector<unsigned char> dataVec(data.begin(), data.end());
    return send(ssl, dataVec);
}

int SecureSocketServer::receive(SSL* ssl, std::vector<unsigned char>& data) {
    if (!ssl) {
        Logger::Error("Invalid SSL object for receiving");
        return -1;
    }
    
    data.resize(4096); // Buffer size
    int ret = SSL_read(ssl, data.data(), data.size());
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN) {
            Logger::Debug("Client closed connection");
            return 0;
        } else if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            Logger::Error("SSL read failed");
            printSSLErrors();
            return -1;
        }
        return 0; // Would block
    }
    
    data.resize(ret);
    return ret;
}

int SecureSocketServer::receive(SSL* ssl, std::string& data) {
    std::vector<unsigned char> dataVec;
    int ret = receive(ssl, dataVec);
    if (ret > 0) {
        data = std::string(dataVec.begin(), dataVec.end());
    }
    return ret;
}

int SecureSocketServer::getServerFd() const {
    return serverFd;
}

void SecureSocketServer::setClientHandler(std::function<void(SSL*, int)> handler) {
    clientHandler = handler;
}

void SecureSocketServer::printSSLErrors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        Logger::Debug("SSL Error: " + std::string(err_buf));
    }
}
