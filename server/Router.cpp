// Handles packet forwarding/NAT (optional).
#include "Router.h"
#include "Logger.h"
#include <arpa/inet.h>
#include <cstring>

Router::Router() : natEnabled(false) {
    Logger::Debug("Router initialized");
}

Router::~Router() {
    Logger::Debug("Router destroyed");
}

bool Router::routePacket(const std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        Logger::Warning("Invalid IP packet received for routing");
        return false;
    }
    
    if (natEnabled) {
        std::vector<unsigned char> modifiedPacket = packet;
        if (!performNAT(modifiedPacket)) {
            Logger::Warning("Failed to perform NAT on packet");
            return false;
        }
        // In a real implementation, you would forward the modified packet
        Logger::Debug("Packet routed with NAT: " + getSourceIP(modifiedPacket) + " -> " + getDestIP(modifiedPacket));
    } else {
        Logger::Debug("Packet routed without NAT: " + getSourceIP(packet) + " -> " + getDestIP(packet));
    }
    
    return true;
}

bool Router::routePacket(const char* packet, size_t length) {
    std::vector<unsigned char> packetVec(packet, packet + length);
    return routePacket(packetVec);
}

bool Router::enableNAT() {
    natEnabled = true;
    Logger::Info("NAT enabled");
    return true;
}

bool Router::disableNAT() {
    natEnabled = false;
    Logger::Info("NAT disabled");
    return true;
}

bool Router::isNATEnabled() const {
    return natEnabled;
}

bool Router::isValidIPPacket(const std::vector<unsigned char>& packet) {
    return isValidIPPacket(reinterpret_cast<const char*>(packet.data()), packet.size());
}

bool Router::isValidIPPacket(const char* packet, size_t length) {
    if (length < sizeof(iphdr)) {
        return false;
    }
    
    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(packet);
    
    // Check IP version
    if ((ipHeader->version & 0xF0) != 0x40) { // IPv4
        return false;
    }
    
    // Check total length
    if (ntohs(ipHeader->tot_len) > length) {
        return false;
    }
    
    return true;
}

std::string Router::getSourceIP(const std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        return "0.0.0.0";
    }
    
    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(packet.data());
    struct in_addr addr;
    addr.s_addr = ipHeader->saddr;
    
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

std::string Router::getDestIP(const std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        return "0.0.0.0";
    }
    
    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(packet.data());
    struct in_addr addr;
    addr.s_addr = ipHeader->daddr;
    
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

uint8_t Router::getProtocol(const std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        return 0;
    }
    
    const iphdr* ipHeader = reinterpret_cast<const iphdr*>(packet.data());
    return ipHeader->protocol;
}

bool Router::performNAT(std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        return false;
    }
    
    iphdr* ipHeader = reinterpret_cast<iphdr*>(packet.data());
    
    // Simple NAT: change source IP to server's external IP
    // In a real implementation, you would maintain a NAT table
    struct in_addr newSrc;
    if (inet_pton(AF_INET, "10.0.0.1", &newSrc) != 1) {
        return false;
    }
    
    ipHeader->saddr = newSrc.s_addr;
    
    // Recalculate checksum (simplified)
    ipHeader->check = 0;
    
    return true;
}

bool Router::reverseNAT(std::vector<unsigned char>& packet) {
    if (!isValidIPPacket(packet)) {
        return false;
    }
    
    iphdr* ipHeader = reinterpret_cast<iphdr*>(packet.data());
    
    // Simple reverse NAT: change destination IP back to original
    // In a real implementation, you would look up the NAT table
    struct in_addr newDest;
    if (inet_pton(AF_INET, "10.0.0.2", &newDest) != 1) {
        return false;
    }
    
    ipHeader->daddr = newDest.s_addr;
    
    // Recalculate checksum (simplified)
    ipHeader->check = 0;
    
    return true;
}
