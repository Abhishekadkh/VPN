// Initializes VPN client, sets up TUN, starts secure connection.
#include "Config.h"
#include "Logger.h"
#include "TunDevice.h"
#include "SecureSocketClient.h"
#include "CryptoHandler.h"
#include "PacketHandler.h"
#include <csignal>
#include <unistd.h>
#include <sys/select.h>
#include <vector>

// Global control for signal handling
volatile bool keepRunning = true;

void signalHandler(int) {
    keepRunning = false;
}

int main() {
    // Initialize logger
    Logger::Inti(LogLevel::DEBUG);
    Logger::Info("Starting VPN Client...");
    
    // Set up signal handling for clean shutdown
    signal(SIGINT, signalHandler);
    
    try {
        // Load configuration
        ClientConfig config;
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
        
        // Initialize secure socket client
        SecureSocketClient client;
        Logger::Status(ConnectionState::CONNECTING);
        
        // Connect to server
        if (!client.connect(config.serverIP, config.serverPort, 
                           config.caCertPath, config.clientCertPath, config.clientKeyPath)) {
            Logger::Error("Failed to connect to server");
            return 1;
        }
        
        Logger::Status(ConnectionState::CONNECTED);
        Logger::Info("Connected to VPN server: " + config.serverIP + ":" + std::to_string(config.serverPort));
        
        // Main packet forwarding loop
        Logger::Info("Starting packet forwarding...");
        
        char tunBuffer[4096];
        std::vector<unsigned char> encryptedBuffer;
        std::vector<unsigned char> decryptedBuffer;
        std::string receivedData;
        uint32_t sequence = 0;
        
        while (keepRunning) {
            fd_set readFds;
            FD_ZERO(&readFds);
            FD_SET(tun.getFd(), &readFds);
            FD_SET(client.getSocketFd(), &readFds);
            
            int maxFd = std::max(tun.getFd(), client.getSocketFd()) + 1;
            
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
            
            // Check TUN device for outgoing packets
            if (FD_ISSET(tun.getFd(), &readFds)) {
                ssize_t len = tun.readPacket(tunBuffer, sizeof(tunBuffer));
                if (len > 0) {
                    Logger::Debug("Read " + std::to_string(len) + " bytes from TUN");
                    
                    // Create packet with header
                    std::vector<unsigned char> packetData(tunBuffer, tunBuffer + len);
                    auto packet = PacketHandler::createPacket(packetData, sequence++);
                    
                    // Encrypt packet
                    auto encrypted = crypto.encrypt(packet);
                    
                    // Send to server
                    int sent = client.send(encrypted);
                    if (sent > 0) {
                        Logger::Debug("Sent " + std::to_string(sent) + " encrypted bytes to server");
                    } else if (sent < 0) {
                        Logger::Error("Failed to send packet to server");
                        break;
                    }
                }
            }
            
            // Check server connection for incoming packets
            if (FD_ISSET(client.getSocketFd(), &readFds)) {
                int received = client.receive(receivedData);
                if (received > 0) {
                    Logger::Debug("Received " + std::to_string(received) + " bytes from server");
                    
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
                        Logger::Warning("Failed to parse packet from server");
                    }
                } else if (received == -2) {
                    Logger::Info("Server closed connection");
                    break;
                } else if (received < 0) {
                    Logger::Error("Failed to receive from server");
                    break;
                }
                // received == 0 means no data available (would block), continue
            }
        }
        
        Logger::Status(ConnectionState::DISCONNECTED);
        Logger::Info("VPN client shutting down...");
        
    } catch (const std::exception& ex) {
        Logger::Error("Exception: " + std::string(ex.what()));
        return 1;
    }
    
    return 0;
}

