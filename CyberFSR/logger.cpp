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


using namespace CyberFSR;

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

std::ofstream logFile("./CyberFSR.log", std::ios::app);

void WriteLogToFile(const LogEntry& logEntry) {
    logFile << logEntry.hardwareInfo << " ::: " << logEntry.message << "\n";
}


void WritingThreadFunction() {
    while (!stopWritingThread) {
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCondVar.wait(lock, [] { return !logQueue.empty() || stopWritingThread; });

        while (!logQueue.empty()) {
            LogEntry entry = std::move(logQueue.front());
            logQueue.pop();
            lock.unlock();

            WriteLogToFile(entry);

            lock.lock();
        }
    }
}

void Logger::init() {
    std::stringstream logStream;
    logStream << "CyberLogger init" << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }


    if (!writingThread.joinable()) {
        stopWritingThread = false;
        writingThread = std::thread(WritingThreadFunction);
    }
}

void Logger::cleanup() {
    std::stringstream logStream;
    logStream << "CyberLogger cleanup" << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << dynamicInfo << " - " << errorInfo << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << " - " << errorInfo << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << staticInfo << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}

void Logger::log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo) {
    std::stringstream logStream;
    logStream << functionName << " - " << errorInfo << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}

void Logger::log(const LogType& logType, const std::string_view& functionName) {
    std::stringstream logStream;
    logStream << functionName << '\n';

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ SystemInfo(), logStream.str() });
    }

    queueCondVar.notify_one();
}
