// Extracts real packets from encrypted stream.
#pragma once

#include <vector>
#include <string>
#include <cstdint>

struct PacketHeader {
    uint32_t magic;      // Magic number to identify packets
    uint32_t length;     // Length of payload
    uint32_t sequence;   // Sequence number for ordering
    uint32_t checksum;   // Simple checksum for integrity
};

class PacketHandler {
public:
    static const uint32_t MAGIC_NUMBER = 0x12345678;
    static const size_t MAX_PACKET_SIZE = 8192;
    
    // Packet creation
    static std::vector<unsigned char> createPacket(const std::vector<unsigned char>& payload, uint32_t sequence = 0);
    static std::vector<unsigned char> createPacket(const std::string& payload, uint32_t sequence = 0);
    
    // Packet parsing
    static bool parsePacket(const std::vector<unsigned char>& data, std::vector<unsigned char>& payload, uint32_t& sequence);
    static bool parsePacket(const std::vector<unsigned char>& data, std::string& payload, uint32_t& sequence);
    
    // Utility functions
    static uint32_t calculateChecksum(const std::vector<unsigned char>& data);
    static bool validatePacket(const std::vector<unsigned char>& data);
    static PacketHeader extractHeader(const std::vector<unsigned char>& data);
};
