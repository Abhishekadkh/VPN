// Stores client configs (server IP, port, certs, TUN name).

#pragma once 

#include <string>

class ClientConfig {
public:
    ClientConfig(const std::string& configPath = "");

    // TUN device
    std::string tunName;

    // Server info
    std::string serverIP;
    int serverPort;

    // TLS (Client side)
    std::string caCertPath;
    std::string clientCertPath;
    std::string clientKeyPath;

    // AES
    std::string aesKey;
    std::string aesIV;

private:
    void loadDefaults();
    void loadFromFile(const std::string& path); 
};

