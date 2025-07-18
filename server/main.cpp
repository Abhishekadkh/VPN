#include "Logger.h"
#include "Config.h"
#include "TunDevice.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <netinet/ip.h>  
#include <arpa/inet.h>
#include <unistd.h>      // For usleep   

using namespace std;

// Global control for signal handling
volatile bool keepRunning = true;

void signalHandler(int) {
    keepRunning = false;
}

void printPacketInfo(const char* packet, int length) {
    if (length < sizeof(iphdr)) {
        Logger::Warning("Packet too short for IP header");
        return;
    }

    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(packet);
    struct in_addr src, dst;
    src.s_addr = ipHeader->saddr;
    dst.s_addr = ipHeader->daddr;

    Logger::Debug("IP Packet: " + std::string(inet_ntoa(src)) +
                  " → " + std::string(inet_ntoa(dst)) +
                  ", Length: " + std::to_string(ntohs(ipHeader->tot_len)) +
                  ", Protocol: " + std::to_string(ipHeader->protocol));
}

int main() {
    // Initialize logger
    Logger::Inti(LogLevel::DEBUG);
    Logger::Info("<========================TESTING LOGGER=======================================>");
    Logger::Info("Server has been started!");
    Logger::Status(ConnectionState::CONNECTING);
    Logger::Warning("Failed to create socket fd!!");
    Logger::Status(ConnectionState::CONNECTED);
    Logger::Debug("Failed to bind socket fd!");
    Logger::Error("Couldn't start server!");
    Logger::Status(ConnectionState::DISCONNECTED);

    // Config test
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
    Logger::Info("================================================================");

    // Set up signal handling for clean shutdown
    signal(SIGINT, signalHandler);

    try {
        Logger::Info("<==================TESTING TUN INTERFACE READ========================>");
        TunDevice tun(config.tunName);

        char buffer[2000];
        Logger::Info("[*] Listening on TUN interface... Press Ctrl+C to stop.");

        while (keepRunning) {
            int len = tun.readPacket(buffer, sizeof(buffer));
            if (len > 0) {
                Logger::Debug("Packet read: " + std::to_string(len) + " bytes");
                printPacketInfo(buffer, len);
            } else if (len == 0) {
                // No data available, sleep briefly to avoid busy waiting
                usleep(10000); // Sleep for 10ms
            }
        }

        Logger::Info("[+] TUN test ended cleanly.");
    } catch (const std::exception& ex) {
        Logger::Error("Exception: " + std::string(ex.what()));
    }

    return 0;
}
