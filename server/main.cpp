// Accepts TLS connections, reads and injects packets.

// <=====================TESTING LOGGER========================================================>

#include "Logger.h"
//#include <iostream>
using namespace std;

int main(){
    Logger::Info("<========================TESTING LOGGER=======================================>");
    Logger::Inti(LogLevel::DEBUG);
    Logger::Info(" Server has been started!");
    Logger::Status(ConnectionState::CONNECTING);
    Logger::Warning(" Failed to create socked fd!!");
    Logger::Status((ConnectionState::CONNECTED));
    Logger::Debug(" Failed to bind socket fd!");
    Logger::Error(" Couldn't start server!");
    Logger::Status(ConnectionState::DISCONNECTED);
    return 0;
}