#pragma once

#include "CyberNGX.h"

#include <queue>
#include <fstream>

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
        INFO_VERBOSE_t,     // Represents an information log type
        WARNING_t,  // Represents a warning log type
        ERROR_t,    // Represents an error log type
        BAD         // Represents an error occurred inside the logger somehow, don't use it
    };

    struct LogEntry {
        LogType type;
        CyberTypes::SystemInfo hardware_info;
        CyberTypes::CyString message;
        CyberTypes::CyString_view function;

        LogEntry(const CyberLogger::LogType&, const CyberTypes::SystemInfo&, const CyberTypes::CyString_view&, const CyberTypes::CyString&);
        LogEntry(const LogEntry& other);
    };


    CyberTypes::CyString_view getLogTypeName(const LogType& logType);



    class Logger {
    public:
        ~Logger();
        Logger();
        Logger(const LPCWSTR& fileName, const bool& doPerformanceInfo, const bool& doCoreInfo, const bool& doRTC);
        void start();
        void stop();

        void logVerboseInfo(const CyberTypes::CyString_view& functionName, const CyberTypes::CyString& message);

        void logInfo(const CyberTypes::CyString_view& functionName, const CyberTypes::CyString& message);
        void logWarning(const CyberTypes::CyString_view& functionName, const CyberTypes::CyString& message);
        void logError(const CyberTypes::CyString_view& functionName, const CyberTypes::CyString& message);

        CyberTypes::CyString FileName;

        bool DoPerformanceInfo = true;
        bool DoCoreInfo = true;
        bool DoRTC = true;

        bool doVerbose = true;

    private:

        StatusContainer LoggerStatus;

        std::atomic<bool> stopWritingThread = false;

        std::queue<LogEntry> logQueue;
        std::mutex queueMutex;
        std::condition_variable queueCondVar;

        std::thread writingThread;

        std::wofstream logFile;

        void WritingThreadFunction();
    };

}  // namespace CyberLogger



CyberTypes::CyString_view to_CyString(const CyberLogger::LogType&);
CyberTypes::CyString to_CyString(const CyberLogger::LogEntry&);


std::wostream& operator<<(std::wostream& os, const CyberLogger::LogType& logType);
std::wostream& operator<<(std::wostream& os, const CyberLogger::LogEntry& entry);