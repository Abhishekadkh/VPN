// Accepts TLS connections, reads and injects packets.

// <=====================TESTING LOGGER========================================================>

#include "Logger.h"
#include "Config.h"

using namespace std;

int main(){
    Logger::Info("<========================TESTING LOGGER=======================================>");
    Logger::Inti(LogLevel::DEBUG);
    Logger::Info(" Server has been started!");
    Logger::Status(ConnectionState::CONNECTING);
    Logger::Warning(" Failed to create socked fd!!");
    Logger::Status((ConnectionState::CONNECTED));
    Logger::Debug(" Failed to bind socket fd!");
    Logger::Error(" Couldn't start server!");
    Logger::Status(ConnectionState::DISCONNECTED);


    Logger::Info("<==================TESTING SERVER CONFIGS WITH LOGGER==============================================>");

    ServerConfig config;

    Logger::Info("==== Server VPN Config ====");

    Logger::Info("TUN Device:         " + config.tunName);
    Logger::Info("Listening Port:     " + std::to_string(config.listenPort));

    Logger::Info("CA Cert Path:       " + config.caCertPath);
    Logger::Info("Server Cert Path:   " + config.serverCertPath);
    Logger::Info("Server Key Path:    " + config.serverKeyPath);

    Logger::Info("AES Key (hex):      " + config.aesKey);
    Logger::Info("AES IV (hex):       " + config.aesIV);

    Logger::Info("============================");

    return 0;
}