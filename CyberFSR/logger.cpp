#include "pch.h"
#include "Logger.h"

#include <iostream>
#include <limits>


#include <Windows.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <string_view>
#include <optional>
#include <array>

#include <atomic>
#include <array>
#include <thread>
#include <vector>
#include <fstream>
#include <mutex>
#include <string_view>
#include <optional>
#include <sstream>

using namespace CyberFSR;

std::mutex fileMutex;

static void WriteToFile(const std::string& logMessage) {
    std::ofstream logFile("./CyberFSR.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << logMessage;
        logFile.close();
    }
}


void Logger::init() {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << "CyberLogger init" << '\n';

    WriteToFile(logStream.str());
}

void Logger::cleanup() {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << "CyberLogger cleanup" << '\n';

    WriteToFile(logStream.str());
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo) {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << dynamicInfo << " - " << errorInfo << '\n';

    WriteToFile(logStream.str());
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo) {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << errorInfo << '\n';

    WriteToFile(logStream.str());
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo) {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << '\n';

    WriteToFile(logStream.str());
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo) {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << functionName << " - " << errorInfo << '\n';

    WriteToFile(logStream.str());
}

void Logger::log(const LogType& logType, const std::string_view& functionName) {
    std::lock_guard<std::mutex> lock(fileMutex);

    std::stringstream logStream;
    logStream << functionName << '\n';

    WriteToFile(logStream.str());
}

