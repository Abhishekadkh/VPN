// TUN read/write for server.
#include "TunDevice.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>      
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <iostream>
#include <system_error>

// these are standard includes for C++17
// fnctl.h is used for file control operations(like read/write and opem/close
// stdexcept is used for exception handling
// cstring is used for memory manipulation functions like memset and strncpy
// linux/if_tun.h is used for TUN/TAP device operations
// sys/ioctl.h is used for device control operations

using namespace std;

// this is the constructor for the TunDevice class
// it initializes the device name and file descriptor, and calls the initialize method
// to set up the TUN device
// deviceName is the name of the TUN device to be created or used
// fd is initialized to -1 to indicate that the device is not yet open
// openFlag is initialized to false to indicate that the device is not open
// initialize() is called to set up the TUN device, which includes allocating it and setting
// later I'll describe about initialize() and cleanup() methods

TunDevice::TunDevice(const std::string& deviceName)
    : deviceName(deviceName), fd(-1), openFlag(false) {
    initialize();
}

// this is the destructor for the TunDevice class
// it calls the cleanup method to close the TUN device and release resources
// cleanup() ensures that the device is properly closed and resources are released
TunDevice::~TunDevice() {
    cleanup();
}

// this method initializes the TUN device by allocating it and setting it to non-blocking mode
// it uses allocateTunDevice to create the device and setNonBlocking to configure it
// if the allocation fails, it throws an error using handleError
// allocateTunDevice is responsible for opening the TUN device and configuring it with the specified name

void TunDevice::initialize() {
    fd = allocateTunDevice(deviceName);
    if (fd < 0) {
        handleError("Failed to allocate TUN device");
    }
    setNonBlocking(fd);
    openFlag = true; // Mark as open after successful allocation
}

// this method cleans up the TUN device by closing it if it is open
// it also closes the file descriptor if it is valid
// cleanup() is called in the destructor to ensure that resources are released when the object is destroyed
// Closes the device if it’s open.
// Resets file descriptor to -1

void TunDevice::cleanup() {
    if (openFlag) {
        close();
    }
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

// this method opens up the TUN device by setting openFlag to true

bool TunDevice::open() {
    if (openFlag) {
        return true; // Already open
    }
    if (fd < 0) {
        handleError("TUN device not allocated");
        return false;
    }
    openFlag = true;
    return true;
}

// this method close up the TUN device by setting openFlag to false

void TunDevice::close() {
    if (!openFlag) {
        return; // Already closed
    }
    ::close(fd);
    fd = -1;
    openFlag = false;
}

// Tries to read data (a packet) from the TUN device.
// If no data is available (because it’s non-blocking), it returns 0.
// If there's an error, it reports and throws an exception.

ssize_t TunDevice::readPacket(void* buffer, size_t length) {
    if (!openFlag) {
        handleError("TUN device is not open");
        return -1;
    }
    ssize_t bytesRead = read(fd, buffer, length);
    if (bytesRead < 0) {
        // For non-blocking mode, EAGAIN/EWOULDBLOCK is normal when no data is available
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // No data available, return 0 instead of error
        }
        handleError("Failed to read from TUN device");
    }
    return bytesRead;
}

// Sends (writes) a packet to the TUN device (like it’s being sent to a network).

ssize_t TunDevice::writePacket(const void* buffer, size_t length) {
    if (!openFlag) {
        handleError("TUN device is not open");
        return -1;
    }
    ssize_t bytesWritten = write(fd, buffer, length);
    if (bytesWritten < 0) {
        handleError("Failed to write to TUN device");
    }
    return bytesWritten;
}

// These are utility functions 
// These are getter methods — they return internal values (name, open status, file descriptor).

std::string TunDevice::getDeviceName() const {
    return deviceName;
}

bool TunDevice::isOpen() const {
    return openFlag;
}

int TunDevice::getFd() const {
    return fd;
}

// Opens the special Linux file that lets us create a virtual network interface.
// returns tunnel file descriptor 
// Handles error if that file can't be opened.

int TunDevice::allocateTunDevice(const std::string& deviceName) {
    struct ifreq ifr;
    int tunFd = ::open("/dev/net/tun", O_RDWR);
    if (tunFd < 0) {
        handleError("Failed to open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device without packet info

    // ifr is a config struct.
    // We set flags saying "make a TUN device" (not TAP) and "no packet info".

    if (!deviceName.empty()) {
        strncpy(ifr.ifr_name, deviceName.c_str(), IFNAMSIZ);
    }

    // If the caller gave a device name (like "tun0"), copying it into ifr.

    if (ioctl(tunFd, TUNSETIFF, &ifr) < 0) {
        handleError("Failed to set TUN device flags");
        ::close(tunFd);
        return -1;
    }

    // Using ioctl() to actually create/configure the device with those flags

    return tunFd;
}

// Get the current flags for the file descriptor
// Check for error
// Add the "non-blocking" flag so reads/writes won’t hang

void TunDevice::setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        handleError("Failed to get file descriptor flags");
        return;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        handleError("Failed to set file descriptor to non-blocking mode");
    }
}

// Prints an error message and throws an exception if something goes wrong.
// strerror(errno) gives a human-readable error description.

void TunDevice::handleError(const std::string& errorMessage) {
    std::cerr << "Error: " << errorMessage << " - " << strerror(errno) << std::endl;
    throw std::runtime_error(errorMessage + ": " + strerror(errno));
}

// desciption : what is the purpose of this file?
// This file implements the TunDevice class, which provides functionality for managing a TUN device in a VPN server context.
// It includes methods for opening, closing, reading from, and writing to the TUN device, as well as error handling and device initialization.
// The class is designed to be used in a server application that requires network tunneling capabilities, such as a VPN server.
// It handles the low-level operations required to interact with the TUN device, ensuring that it is properly configured and ready for use.
// This implementation is crucial for the server's ability to read and write network packets through the TUN interface.
// It also includes error handling to manage issues that may arise during device operations.

// WORKING 
/*
==============================
 TUN Device Workflow Overview
==============================

This class manages a virtual TUN device for use in a VPN server. Here's the typical usage workflow:

1. Create a TUN Device Object:
   --------------------------------
   TunDevice tun("tun0"); 
   // This automatically allocates and configures the "tun0" interface.

2. Read Incoming Packets (from system/network):
   --------------------------------
   char buffer[1500]; // typical MTU size
   ssize_t n = tun.readPacket(buffer, sizeof(buffer));
   if (n > 0) {
       // Process incoming packet in 'buffer'
   }

3. Write Outgoing Packets (to system/network):
   --------------------------------
   tun.writePacket(buffer, n); 
   // Send a processed or new packet back through the tunnel.

4. Non-blocking I/O:
   --------------------------------
   The TUN file descriptor is set to non-blocking mode.
   If no data is available, readPacket() will return 0 instead of freezing.

5. Device Status Checks (optional):
   --------------------------------
   tun.isOpen();      // Check if TUN is currently open
   tun.getFd();       // Get the file descriptor
   tun.getDeviceName(); // Get the name of the TUN interface (e.g., "tun0")

6. Cleanup (automatic or manual):
   --------------------------------
   When the object goes out of scope, the destructor calls cleanup().
   Alternatively, you can call tun.close() manually.

===========================================
 Summary:
 This class provides a high-level interface
 to open, configure, read from, and write to
 a TUN device, making it suitable for VPN or
 tunneling applications.
===========================================
*/

// CONSCLUSION 
/*
This class is like a "translator" between our program and the Linux virtual networking system. It:

    Opens a virtual network interface (/dev/net/tun).

    Reads and writes raw IP packets like a real network card.

    Cleans up after itself.

    Makes sure errors are reported properly.
*/