// Stores client configs (server IP, port, certs, TUN name).

#include "Config.h"
#include <iostream>

ClientConfig::ClientConfig(const std::string& configPath) {
    if (!configPath.empty()) {
        loadFromFile(configPath);
    } else {
        loadDefaults();
    }
}

void ClientConfig::loadDefaults() {
    tunName = "tun1";

    serverIP = "127.0.0.1";
    serverPort = 4433;

    caCertPath     = "certs/ca.crt";
    clientCertPath = "certs/client.crt";
    clientKeyPath  = "certs/client.key";

    aesKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    aesIV  = "abcdef9876543210abcdef9876543210";
}

void ClientConfig::loadFromFile(const std::string& path) {
    std::cerr << "[ClientConfig] Config file parsing not implemented. Using defaults.\n";
    loadDefaults();
}
