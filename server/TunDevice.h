// TUN read/write for server.
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

/*
==========================================================
 TunDevice.h - Header for TUN Interface Management Class
==========================================================

Description:
------------
This header declares the `TunDevice` class, which provides
an abstraction for working with a TUN (virtual network) 
device on Linux. It is designed for use in a VPN server 
or any application requiring low-level access to IP packets.

A TUN device acts like a virtual network interface and allows 
user-space programs to read and write raw IP packets.

Key Features:
-------------
- Automatically allocates and configures a TUN device (e.g., tun0)
- Non-blocking I/O for seamless integration into event loops
- Read/write IP packets as raw data
- Manages resource cleanup and error handling

Public Methods:
---------------
- Constructor / Destructor:
    TunDevice(const std::string& deviceName);
    ~TunDevice();

- Device Control:
    bool open();               // Mark the TUN device as open
    void close();              // Close the TUN device

- Packet I/O:
    ssize_t readPacket(void* buffer, size_t length);       // Read a packet
    ssize_t writePacket(const void* buffer, size_t length); // Write a packet

- Info Accessors:
    std::string getDeviceName() const;  // Get name (e.g., "tun0")
    bool isOpen() const;                // Check if device is open
    int getFd() const;                  // Get file descriptor

Private Helpers:
----------------
- initialize()          : Internal setup logic
- cleanup()             : Cleanup logic on destruction
- allocateTunDevice()   : Creates/configures TUN device
- setNonBlocking()      : Sets the device to non-blocking mode
- handleError()         : Reports and throws exceptions on errors

Usage Summary:
--------------
1. Create a `TunDevice` object with the desired name (e.g., "tun0").
2. Read from or write to the device using readPacket/writePacket.
3. Check device status via isOpen() and getFd() if needed.
4. Cleanup is automatic via the destructor or can be done manually.

Note:
-----
This header should be included wherever you need to interact
with the TUN device, such as in the VPN server main loop.

==========================================================
*/
