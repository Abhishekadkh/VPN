// Server port, certs, routing settings.

#include "Config.h"
#include <iostream>

ServerConfig::ServerConfig(const std::string& configPath) {
    if (!configPath.empty()) {
        loadFromFile(configPath);
    } else {
        loadDefaults();
    }
}

void ServerConfig::loadDefaults() {
    tunName = "tun0";

    listenPort = 4433;

    caCertPath     = "certs/ca.crt";
    serverCertPath = "certs/server.crt";
    serverKeyPath  = "certs/server.key";

    aesKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    aesIV  = "abcdef9876543210abcdef9876543210";
}

void ServerConfig::loadFromFile(const std::string& path) {
    std::cerr << "[ServerConfig] Config file parsing not implemented. Using defaults.\n";
    loadDefaults();
}
