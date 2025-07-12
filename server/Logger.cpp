// Server-side logging.
#include "Logger.h"
#include <iostream>
#include <mutex>
#include <string>

using namespace std;

LogLevel Logger::currentLevel = LogLevel::INFO;
mutex logMutex;

void Logger::Inti(LogLevel level){
    currentLevel = level;
}

void Logger::Log(const string& levelStr, const string& message, const string& color){
    lock_guard<mutex>lock(logMutex);
    cout<<color<<"["<<levelStr<<"]"<<message<<"\033[0m"<<endl;
}

void Logger::Info(const std::string& msg) {
    if ((int)currentLevel >= (int)LogLevel::INFO)
        Log("INFO", msg, "\033[1;32m"); 
}

void Logger::Warning(const std::string& msg) {
    if ((int)currentLevel >= (int)LogLevel::WARNING)
        Log("WARNING", msg, "\033[1;33m"); 
}

void Logger::Error(const std::string& msg) {
    if ((int)currentLevel >= (int)LogLevel::ERROR)
        Log("ERROR", msg, "\033[1;31m");
}

void Logger::Debug(const std::string& msg) {
    if ((int)currentLevel >= (int)LogLevel::DEBUG)
        Log("DEBUG", msg, "\033[1;34m"); 
}

void Logger::Status(const std::string& msg) {
    Log("STATUS", msg, "\033[1;36m");  
}


void Logger::Status(ConnectionState state) {
    switch (state) {
        case ConnectionState::CONNECTING:
            Status("Connecting to VPN...");
            break;
        case ConnectionState::CONNECTED:
            Status("VPN connected.");
            break;
        case ConnectionState::DISCONNECTED:
            Status("VPN disconnected.");
            break;
    }
}
