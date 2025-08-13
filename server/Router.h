// Handles packet forwarding/NAT (optional).
#pragma once

#include <vector>
#include <string>
#include <netinet/ip.h>

class Router {
public:
    Router();
    ~Router();
    
    // Basic packet routing
    bool routePacket(const std::vector<unsigned char>& packet);
    bool routePacket(const char* packet, size_t length);
    
    // NAT functions (simplified)
    bool enableNAT();
    bool disableNAT();
    bool isNATEnabled() const;
    
    // Utility functions
    static bool isValidIPPacket(const std::vector<unsigned char>& packet);
    static bool isValidIPPacket(const char* packet, size_t length);
    static std::string getSourceIP(const std::vector<unsigned char>& packet);
    static std::string getDestIP(const std::vector<unsigned char>& packet);
    static uint8_t getProtocol(const std::vector<unsigned char>& packet);

private:
    bool natEnabled;
    
    // Simple NAT table (in a real implementation, this would be more complex)
    std::string natSourceIP;
    std::string natDestIP;
    
    bool performNAT(std::vector<unsigned char>& packet);
    bool reverseNAT(std::vector<unsigned char>& packet);
};
