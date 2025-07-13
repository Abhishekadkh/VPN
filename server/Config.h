// Server port, certs, routing settings.

#pragma once
#include <string>

class ServerConfig {
public:
    ServerConfig(const std::string& configPath = "");

    // TUN device
    std::string tunName;

    // Listener info
    int listenPort;

    // TLS (Server side)
    std::string caCertPath;
    std::string serverCertPath;
    std::string serverKeyPath;

    // AES
    std::string aesKey;
    std::string aesIV;

private:
    void loadDefaults();
    void loadFromFile(const std::string& path); 
};

