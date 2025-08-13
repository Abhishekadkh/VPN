// Manages TLS client connection to server.
#pragma once

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class SecureSocketClient {
public:
    SecureSocketClient();
    ~SecureSocketClient();
    
    // Connection management
    bool connect(const std::string& serverIP, int port, 
                 const std::string& caCertPath, 
                 const std::string& clientCertPath, 
                 const std::string& clientKeyPath);
    void disconnect();
    bool isConnected() const;
    
    // Data transmission
    int send(const std::vector<unsigned char>& data);
    int send(const std::string& data);
    int receive(std::vector<unsigned char>& data);
    int receive(std::string& data);
    
    // Utility
    int getSocketFd() const;

private:
    SSL* ssl;
    SSL_CTX* ctx;
    int sockfd;
    bool connected;
    
    void initializeSSL();
    void cleanupSSL();
    bool setupSSLContext(const std::string& caCertPath, 
                        const std::string& clientCertPath, 
                        const std::string& clientKeyPath);
    void printSSLErrors();
};
