// Logs errors, info.

// client-side logging.

#pragma once 
#include <string>

enum class LogLevel{
    INFO,
    WARNING,
    ERROR,
    DEBUG
};

enum class ConnectionState {
    CONNECTING,
    CONNECTED,
    DISCONNECTED
};

using namespace std;

class Logger{
public:
    static void Inti(LogLevel level = LogLevel::INFO);
    static void Info(const string& message);
    static void Warning(const string& message);
    static void Error(const string& message);
    static void Debug(const string& message);
    static void Status(const std::string& msg);
    static void Status(ConnectionState state); // using overloaded functions  

private:
    static LogLevel currentLevel;
    static void Log(const string& levelStr, const string& message, const string& color);
};