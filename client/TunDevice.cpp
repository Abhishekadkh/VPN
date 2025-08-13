// Handles reading/writing packets to TUN interface.
#include "TunDevice.h"
#include "Logger.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <cstring>
#include <stdexcept>

TunDevice::TunDevice(const std::string& deviceName) 
    : deviceName(deviceName), fd(-1), openFlag(false) {
    initialize();
}

TunDevice::~TunDevice() {
    cleanup();
}

void TunDevice::initialize() {
    // Nothing to initialize here
}

void TunDevice::cleanup() {
    close();
}

int TunDevice::allocateTunDevice(const std::string& deviceName) {
    struct ifreq ifr;
    int fd, err;
    
    if ((fd = ::open("/dev/net/tun", O_RDWR)) < 0) {
        Logger::Error("Failed to open /dev/net/tun");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, deviceName.c_str(), IFNAMSIZ);
    
    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        Logger::Error("Failed to create TUN device: " + deviceName);
        ::close(fd);
        return -1;
    }
    
    return fd;
}

bool TunDevice::open() {
    if (openFlag) {
        Logger::Warning("TUN device already open");
        return true;
    }
    
    fd = allocateTunDevice(deviceName);
    if (fd < 0) {
        return false;
    }
    
    setNonBlocking(fd);
    openFlag = true;
    
    Logger::Info("TUN device opened: " + deviceName);
    return true;
}

void TunDevice::close() {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
    openFlag = false;
    Logger::Debug("TUN device closed: " + deviceName);
}

ssize_t TunDevice::readPacket(void* buffer, size_t length) {
    if (!openFlag || fd < 0) {
        Logger::Error("TUN device not open");
        return -1;
    }
    
    ssize_t n = ::read(fd, buffer, length);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            Logger::Error("Failed to read from TUN device");
        }
        return -1;
    }
    
    return n;
}

ssize_t TunDevice::writePacket(const void* buffer, size_t length) {
    if (!openFlag || fd < 0) {
        Logger::Error("TUN device not open");
        return -1;
    }
    
    ssize_t n = ::write(fd, buffer, length);
    if (n < 0) {
        Logger::Error("Failed to write to TUN device");
        return -1;
    }
    
    return n;
}

std::string TunDevice::getDeviceName() const {
    return deviceName;
}

bool TunDevice::isOpen() const {
    return openFlag && fd >= 0;
}

int TunDevice::getFd() const {
    return fd;
}

void TunDevice::setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        Logger::Error("Failed to get file descriptor flags");
        return;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        Logger::Error("Failed to set non-blocking mode");
    }
}

void TunDevice::handleError(const std::string& errorMessage) {
    Logger::Error("TUN Device Error: " + errorMessage);
}
