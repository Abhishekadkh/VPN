// Initializes VPN client, sets up TUN, starts secure connection.

// <==================TESTING CONFIGS WITH LOGGER==============================================>
#include "Config.h"
#include "Logger.h"

int main() {
    ClientConfig config;

    Logger::Info("==== Client VPN Config ====");

    Logger::Info("TUN Device:         " + config.tunName);
    Logger::Info("Server IP:          " + config.serverIP);
    Logger::Info("Server Port:        " + std::to_string(config.serverPort));

    Logger::Info("CA Cert Path:       " + config.caCertPath);
    Logger::Info("Client Cert Path:   " + config.clientCertPath);
    Logger::Info("Client Key Path:    " + config.clientKeyPath);

    Logger::Info("AES Key (hex):      " + config.aesKey);
    Logger::Info("AES IV (hex):       " + config.aesIV);

    Logger::Info("============================");

    return 0;
}

