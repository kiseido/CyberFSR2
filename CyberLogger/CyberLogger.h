#include "pch.h"

#ifndef CyberLOGGER_H
#define CyberLOGGER_H

#include <fstream>
#include <sstream>
#include <string_view>
#include <atomic>
#include <thread>
#include <queue>
#include <memory>
#include <iostream>
#include <ctime>
#include <mutex>
#include <windows.h>

namespace CyberLogger {

    enum LoggerStatus {
        Fresh,
        Starting,
        Running,
        Stopping,
        Stopped
    };

    struct StatusContainer {
        LoggerStatus status;
        std::mutex statusLock;

        StatusContainer();
    };

    enum LogType {
        CLEAN,      // Represents a clean state of the logger
        INFO_t,     // Represents an information log type
        WARNING_t,  // Represents a warning log type
        ERROR_t,    // Represents an error log type
        BAD         // Represents an error occurred inside the logger somehow, don't use it
    };

    struct HighPerformanceCounterInfo {
        LARGE_INTEGER frequency;
        LARGE_INTEGER counter;

        HighPerformanceCounterInfo();
        HighPerformanceCounterInfo(bool performInitLogic);
    };

    struct CoreInfo {
        int logicalProcessorId;
        long long processorTick;

        CoreInfo();
        CoreInfo(bool performInitLogic);
    };

    struct RTC {
        std::chrono::system_clock::time_point timestamp;

        RTC();
        RTC(bool performInitLogic);
    };

    struct SystemInfo {
        CoreInfo coreInfo;
        HighPerformanceCounterInfo highPerformanceCounterInfo;
        RTC rtc;

        bool DoPerformanceInfo;
        bool DoCoreInfo;
        bool DoRTC;

        SystemInfo(bool doCoreInfo, bool doPerformanceInfo, bool doRTC);
    };

    struct LogEntry {
        SystemInfo hardwareInfo;
        std::string message;
    };

    struct Logger {
        ~Logger();
        Logger();

        void start(const LPCWSTR fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC);
        void stop();
        void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo, bool doPerfInfo = false);
        void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo, bool doPerfInfo = false);
        void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, bool doPerfInfo = false);
        void log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo, bool doPerfInfo = false);
        void log(const LogType& logType, const std::string_view& functionName, bool doPerfInfo = false);

        std::string FileName;

        bool DoPerformanceInfo;
        bool DoCoreInfo;
        bool DoRTC;

    private:

        StatusContainer LoggerStatus;

        std::atomic<bool> stopWritingThread;

        std::queue<LogEntry> logQueue;
        std::mutex queueMutex;
        std::condition_variable queueCondVar;

        std::thread writingThread;

        std::ofstream logFile;

        void WritingThreadFunction();
    };

    std::string LPCWSTRToString(LPCWSTR lpcwstr);


    template<typename... Args>
    std::string convertToString(const std::string& str, Args&&... args) {
        std::stringstream ss;
        (ss << ... << std::forward<Args>(args));
        return ss.str();
    };



}  // namespace CyberLogger

#endif
