#include "pch.h"
#include "Logger.h"

#include <fstream>
#include <sstream>
#include <string_view>
#include <atomic>
#include <thread>
#include <queue>
#include <memory>
#include <iostream>
#include <ctime>
#include <windows.h>

bool UseLogWindow = true;

struct HighPerformanceCounterInfo {
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    friend std::ostream& operator<<(std::ostream& os, const HighPerformanceCounterInfo& counterInfo) {
        os << counterInfo.counter.QuadPart;
        os << " / ";
        os << counterInfo.frequency.QuadPart;
        return os;
    }
};

struct SystemInfo {
    int logicalProcessorId;
    long long processorTick;
    HighPerformanceCounterInfo highPerformanceCounterInfo;
    std::chrono::system_clock::time_point rtc;



    static inline int GetLogicalProcessorId() {
        return GetCurrentProcessorNumber();
    }

    static inline long long GetProcessorTick() {
        return __rdtsc();
    }

    static inline HighPerformanceCounterInfo GetHighPerformanceCounterInfo() {
        LARGE_INTEGER frequency, counter;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
        return { frequency, counter };
    }

    static inline auto GetRTC() {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        return now;
    }

    friend std::ostream& operator<<(std::ostream& os, const SystemInfo& systemInfo) {
        os << "Core: " << systemInfo.logicalProcessorId;
        os << " -- ";
        os << "Tick: " << systemInfo.processorTick;
        os << " -- ";
        os << "HPC: " << systemInfo.highPerformanceCounterInfo;
        os << " -- ";
        os << "RTC: " << systemInfo.rtc;

        return os;
    }

    SystemInfo() :
        logicalProcessorId(GetLogicalProcessorId()),
        processorTick(GetProcessorTick()),
        highPerformanceCounterInfo(GetHighPerformanceCounterInfo()),
        rtc(GetRTC()) {}
};

struct LogEntry {
    SystemInfo hardwareInfo;
    std::string message;
};

std::atomic<bool> stopWritingThread(false);
std::queue<LogEntry> logQueue;
std::mutex queueMutex;
std::condition_variable queueCondVar;
std::thread writingThread;

std::ofstream logFile;

std::string CyberLogger::convertLPCWSTRToString(LPCWSTR lpcwstr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, lpcwstr, -1, nullptr, 0, nullptr, nullptr);
    if (size == 0)
        return ""; // Error occurred

    std::string str(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, lpcwstr, -1, str.data(), size, nullptr, nullptr);

    return str;
}

void WritingThreadFunction() {
    if (! logFile.is_open())
      logFile.open("./CyberInterposer.log", std::ios::app);

    while (!stopWritingThread) {
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCondVar.wait(lock, [] { return !logQueue.empty() || stopWritingThread; });

        while (!logQueue.empty()) {
            lock.unlock();
            LogEntry entry = std::move(logQueue.front());
            logQueue.pop();
            lock.lock();

            logFile << entry.hardwareInfo << " ::: " << entry.message << "\n";
        }
    }

    logFile.close();
}

void CyberLogger::init() {
    std::stringstream logStream;
    logStream << "CyberLogger init" << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }


    if (!writingThread.joinable()) {
        stopWritingThread = false;
        writingThread = std::thread(WritingThreadFunction);
    }
}

void CyberLogger::cleanup() {
    std::stringstream logStream;
    logStream << "CyberLogger cleanup" << '\n';
    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
    stopWritingThread.store(true);
}

void CyberLogger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << dynamicInfo << " - " << errorInfo << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
}

void CyberLogger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << errorInfo << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
}

void CyberLogger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
}

void CyberLogger::log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << errorInfo << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
}

void CyberLogger::log(const LogType& logType, const std::string_view& functionName) {
    std::stringstream logStream;
    logStream << functionName << '\n';

    auto string = logStream.str();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), string });
    }

    queueCondVar.notify_one();
}



