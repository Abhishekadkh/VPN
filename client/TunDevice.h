// Handles reading/writing packets to TUN interface.
#pragma once

#include <string>

class TunDevice {
public:
    TunDevice(const std::string& deviceName);
    ~TunDevice();
    
    bool open();
    void close();
    ssize_t readPacket(void* buffer, size_t length);
    ssize_t writePacket(const void* buffer, size_t length);
    std::string getDeviceName() const;
    bool isOpen() const;
    int getFd() const;

private:
    std::string deviceName;
    int fd;
    bool openFlag;
    void initialize();
    void cleanup();
    void setNonBlocking(int fd);
    void handleError(const std::string& errorMessage);
    int allocateTunDevice(const std::string& deviceName);
};
