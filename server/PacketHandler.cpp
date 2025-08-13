// Extracts real packets from encrypted stream.
#include "PacketHandler.h"
#include "Logger.h"
#include <cstring>
#include <algorithm>

std::vector<unsigned char> PacketHandler::createPacket(const std::vector<unsigned char>& payload, uint32_t sequence) {
    if (payload.size() > MAX_PACKET_SIZE - sizeof(PacketHeader)) {
        Logger::Error("Payload too large for packet");
        return {};
    }
    
    PacketHeader header;
    header.magic = MAGIC_NUMBER;
    header.length = payload.size();
    header.sequence = sequence;
    header.checksum = 0; // Will be calculated after
    
    std::vector<unsigned char> packet;
    packet.resize(sizeof(PacketHeader) + payload.size());
    
    // Copy header
    std::memcpy(packet.data(), &header, sizeof(PacketHeader));
    
    // Copy payload
    if (!payload.empty()) {
        std::memcpy(packet.data() + sizeof(PacketHeader), payload.data(), payload.size());
    }
    
    // Calculate and set checksum
    header.checksum = calculateChecksum(payload);
    std::memcpy(packet.data() + offsetof(PacketHeader, checksum), &header.checksum, sizeof(uint32_t));
    
    return packet;
}

std::vector<unsigned char> PacketHandler::createPacket(const std::string& payload, uint32_t sequence) {
    std::vector<unsigned char> payloadVec(payload.begin(), payload.end());
    return createPacket(payloadVec, sequence);
}

bool PacketHandler::parsePacket(const std::vector<unsigned char>& data, std::vector<unsigned char>& payload, uint32_t& sequence) {
    if (!validatePacket(data)) {
        return false;
    }
    
    PacketHeader header = extractHeader(data);
    sequence = header.sequence;
    
    payload.resize(header.length);
    if (header.length > 0) {
        std::memcpy(payload.data(), data.data() + sizeof(PacketHeader), header.length);
    }
    
    return true;
}

bool PacketHandler::parsePacket(const std::vector<unsigned char>& data, std::string& payload, uint32_t& sequence) {
    std::vector<unsigned char> payloadVec;
    bool success = parsePacket(data, payloadVec, sequence);
    if (success) {
        payload = std::string(payloadVec.begin(), payloadVec.end());
    }
    return success;
}

uint32_t PacketHandler::calculateChecksum(const std::vector<unsigned char>& data) {
    uint32_t checksum = 0;
    for (unsigned char byte : data) {
        checksum = (checksum << 1) + byte;
    }
    return checksum;
}

bool PacketHandler::validatePacket(const std::vector<unsigned char>& data) {
    if (data.size() < sizeof(PacketHeader)) {
        Logger::Warning("Packet too small to contain header");
        return false;
    }
    
    PacketHeader header = extractHeader(data);
    
    // Check magic number
    if (header.magic != MAGIC_NUMBER) {
        Logger::Warning("Invalid magic number in packet");
        return false;
    }
    
    // Check packet size
    if (data.size() != sizeof(PacketHeader) + header.length) {
        Logger::Warning("Packet size mismatch");
        return false;
    }
    
    // Check payload size
    if (header.length > MAX_PACKET_SIZE - sizeof(PacketHeader)) {
        Logger::Warning("Payload too large");
        return false;
    }
    
    // Verify checksum
    std::vector<unsigned char> payload(header.length);
    if (header.length > 0) {
        std::memcpy(payload.data(), data.data() + sizeof(PacketHeader), header.length);
    }
    
    uint32_t calculatedChecksum = calculateChecksum(payload);
    if (calculatedChecksum != header.checksum) {
        Logger::Warning("Checksum mismatch");
        return false;
    }
    
    return true;
}

PacketHeader PacketHandler::extractHeader(const std::vector<unsigned char>& data) {
    PacketHeader header;
    std::memcpy(&header, data.data(), sizeof(PacketHeader));
    return header;
}
