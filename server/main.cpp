#include "Logger.h"
#include "Config.h"
#include "TunDevice.h"
#include "SecureSocketServer.h"
#include "CryptoHandler.h"
#include "PacketHandler.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <netinet/ip.h>  
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <vector>
#include <map>
#include <openssl/ssl.h>
#include <cstdio>
#include <algorithm>

using namespace std;

// Global control for signal handling
volatile bool keepRunning = true;

void signalHandler(int) {
    keepRunning = false;
}

void printPacketInfo(const char* packet, int length) {
    if (length < (int)sizeof(iphdr)) {
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
                  ", Protocol: " + std::to_string(ipHeader->protocol) +
                  ", Version: " + std::to_string(ipHeader->version));
}

int main() {
    // Initialize logger
    Logger::Inti(LogLevel::DEBUG);
    Logger::Info("Starting VPN Server...");
    
    // Set up signal handling for clean shutdown
    signal(SIGINT, signalHandler);

    try {
        // Load configuration
        ServerConfig config;
        Logger::Info("Configuration loaded successfully");
        
        // Initialize crypto handler
        CryptoHandler crypto(config.aesKey, config.aesIV);
        Logger::Info("Crypto handler initialized");
        
        // Initialize TUN device
        TunDevice tun(config.tunName);
        if (!tun.open()) {
            Logger::Error("Failed to open TUN device");
            return 1;
        }
        Logger::Info("TUN device opened: " + tun.getDeviceName());
        
        // Initialize secure socket server
        SecureSocketServer server;
        if (!server.start(config.listenPort, config.caCertPath, 
                         config.serverCertPath, config.serverKeyPath)) {
            Logger::Error("Failed to start server");
            return 1;
        }
        
        Logger::Info("Server started and listening on port " + std::to_string(config.listenPort));
        
        // Client management
        std::map<int, SSL*> clients; // clientFd -> SSL*
        std::map<SSL*, int> clientFds; // SSL* -> clientFd
        
        // Main server loop
        Logger::Info("Starting server main loop...");
        Logger::Info("TUN device monitoring disabled - waiting for client connections");
        
        char tunBuffer[4096];
        std::vector<unsigned char> encryptedBuffer;
        std::vector<unsigned char> decryptedBuffer;
        std::string receivedData;
        uint32_t sequence = 0;
        
        while (keepRunning) {
            fd_set readFds;
            FD_ZERO(&readFds);
            
            // Only monitor TUN device when clients are connected
            if (!clients.empty()) {
                FD_SET(tun.getFd(), &readFds);
                // Logger::Debug("TUN device monitoring enabled (clients connected: " + std::to_string(clients.size()) + ")");
            } else {
                // Logger::Debug("TUN device monitoring disabled (no clients connected)");
            }
            
            FD_SET(server.getServerFd(), &readFds);
            
            // Add all client sockets
            int maxFd = server.getServerFd();
            if (!clients.empty()) {
                maxFd = std::max(maxFd, tun.getFd());
            }
            for (const auto& client : clients) {
                FD_SET(client.first, &readFds);
                maxFd = std::max(maxFd, client.first);
            }
            maxFd++;
            
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            int activity = select(maxFd, &readFds, nullptr, nullptr, &timeout);
            if (activity < 0) {
                if (errno != EINTR) {
                    Logger::Error("Select error");
                    break;
                }
                continue;
            }
            
            // Check for new client connections
            if (FD_ISSET(server.getServerFd(), &readFds)) {
                SSL* clientSSL = nullptr;
                int clientFd = -1;
                
                if (server.acceptClient(clientSSL, clientFd)) {
                    clients[clientFd] = clientSSL;
                    clientFds[clientSSL] = clientFd;
                    Logger::Info("New client connected, total clients: " + std::to_string(clients.size()));
                    
                    // Enable TUN monitoring now that we have clients
                    Logger::Info("TUN device monitoring enabled for new client");
                }
            }
            
            // Check TUN device for outgoing packets ONLY if clients exist
            if (!clients.empty() && FD_ISSET(tun.getFd(), &readFds)) {
                ssize_t len = tun.readPacket(tunBuffer, sizeof(tunBuffer));
                if (len > 0) {
                    Logger::Debug("Read " + std::to_string(len) + " bytes from TUN");
                    printPacketInfo(tunBuffer, len);
                    
                    // Create packet with header
                    std::vector<unsigned char> packetData(tunBuffer, tunBuffer + len);
                    auto packet = PacketHandler::createPacket(packetData, sequence++);
                    
                    // Encrypt packet
                    auto encrypted = crypto.encrypt(packet);
                    
                    // Send to all connected clients
                    std::vector<int> disconnectedClients;
                    for (const auto& client : clients) {
                        int sent = server.send(client.second, encrypted);
                        if (sent > 0) {
                            Logger::Debug("Sent " + std::to_string(sent) + " encrypted bytes to client");
                        } else if (sent < 0) {
                            Logger::Warning("Failed to send to client, marking for disconnect");
                            disconnectedClients.push_back(client.first);
                        }
                    }
                    
                    // Clean up disconnected clients
                    for (int fd : disconnectedClients) {
                        SSL* ssl = clients[fd];
                        server.closeClient(ssl, fd);
                        clients.erase(fd);
                        clientFds.erase(ssl);
                        Logger::Info("Client disconnected, remaining clients: " + std::to_string(clients.size()));
                        
                        // Disable TUN monitoring if no clients remain
                        if (clients.empty()) {
                            Logger::Info("TUN device monitoring disabled (no clients remaining)");
                        }
                    }
                }
            } else if (FD_ISSET(tun.getFd(), &readFds) && clients.empty()) {
                // Clear any pending TUN data without processing (safety measure)
                char tempBuffer[1024];
                ssize_t cleared = tun.readPacket(tempBuffer, sizeof(tempBuffer));
                if (cleared > 0) {
                    Logger::Debug("Cleared " + std::to_string(cleared) + " bytes from TUN (no clients connected)");
                }
            }
            
            // Check client connections for incoming packets
            std::vector<int> disconnectedClients;
            for (const auto& client : clients) {
                if (FD_ISSET(client.first, &readFds)) {
                    int received = server.receive(client.second, receivedData);
                    if (received > 0) {
                        Logger::Debug("Received " + std::to_string(received) + " bytes from client");
                        
                        // Convert to vector
                        std::vector<unsigned char> encryptedData(receivedData.begin(), receivedData.end());
                        
                        // Decrypt packet
                        auto decrypted = crypto.decrypt(encryptedData);
                        
                        // Parse packet
                        std::vector<unsigned char> payload;
                        uint32_t seq;
                        if (PacketHandler::parsePacket(decrypted, payload, seq)) {
                            Logger::Debug("Parsed packet with sequence " + std::to_string(seq));
                            
                            // Write to TUN device
                            ssize_t written = tun.writePacket(payload.data(), payload.size());
                            if (written > 0) {
                                Logger::Debug("Wrote " + std::to_string(written) + " bytes to TUN");
                            } else {
                                Logger::Error("Failed to write packet to TUN");
                            }
                        } else {
                            Logger::Warning("Failed to parse packet from client");
                        }
                    } else if (received == 0) {
                        Logger::Info("Client closed connection");
                        disconnectedClients.push_back(client.first);
                    } else if (received < 0) {
                        Logger::Warning("Failed to receive from client");
                        disconnectedClients.push_back(client.first);
                    }
                }
            }
            
            // Clean up disconnected clients
            for (int fd : disconnectedClients) {
                SSL* ssl = clients[fd];
                server.closeClient(ssl, fd);
                clients.erase(fd);
                clientFds.erase(ssl);
                Logger::Info("Client disconnected, remaining clients: " + std::to_string(clients.size()));
                
                // Disable TUN monitoring if no clients remain
                if (clients.empty()) {
                    Logger::Info("TUN device monitoring disabled (no clients remaining)");
                }
            }
            
            // Periodic status logging when no clients
            static int idleCounter = 0;
            if (clients.empty()) {
                idleCounter++;
                if (idleCounter >= 30) { // Log every 30 seconds (30 * 1 second timeout)
                    Logger::Info("Server idle - waiting for client connections on port 4433");
                    idleCounter = 0;
                }
            } else {
                idleCounter = 0; // Reset counter when clients are connected
            }
        }
        
        Logger::Info("Server shutting down...");
        
        // Clean up all client connections
        for (const auto& client : clients) {
            server.closeClient(client.second, client.first);
        }
        
    } catch (const std::exception& ex) {
        Logger::Error("Exception: " + std::string(ex.what()));
    }

    return 0;
}
