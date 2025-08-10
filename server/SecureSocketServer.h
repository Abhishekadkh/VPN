// TLS listener for encrypted sessions.
#pragma once

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <functional>

class SecureSocketServer {
public:
    SecureSocketServer();
    ~SecureSocketServer();
    
    // Server management
    bool start(int port, const std::string& caCertPath, 
               const std::string& serverCertPath, 
               const std::string& serverKeyPath);
    void stop();
    bool isRunning() const;
    
    // Client connection handling
    bool acceptClient(SSL*& clientSSL, int& clientFd);
    void closeClient(SSL* clientSSL, int clientFd);
    
    // Data transmission
    int send(SSL* ssl, const std::vector<unsigned char>& data);
    int send(SSL* ssl, const std::string& data);
    int receive(SSL* ssl, std::vector<unsigned char>& data);
    int receive(SSL* ssl, std::string& data);
    
    // Utility
    int getServerFd() const;
    void setClientHandler(std::function<void(SSL*, int)> handler);

private:
    SSL_CTX* ctx;
    int serverFd;
    bool running;
    std::function<void(SSL*, int)> clientHandler;
    
    void initializeSSL();
    void cleanupSSL();
    bool setupSSLContext(const std::string& caCertPath, 
                        const std::string& serverCertPath, 
                        const std::string& serverKeyPath);
    void printSSLErrors();
};
