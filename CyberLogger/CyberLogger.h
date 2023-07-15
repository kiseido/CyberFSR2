#include "pch.h"

#ifndef CyberLOGGER_H
#define LOGGER_H

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
    };  

    enum LogType {
        CLEAN,      // Represents a clean state of the logger
        INFO_t,     // Represents an information log type
        WARNING_t,  // Represents a warning log type
        ERROR_t,    // Represents an error log type
        BAD         // Represents an error occured inide the logger somehow, don't use it
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

        StatusContainer LoggerStatus;

        bool UseLogWindow;
        bool DoPerformanceInfo;
        bool DoCoreInfo;
        bool DoRTC;

    private:
        struct HighPerformanceCounterInfo {
            LARGE_INTEGER frequency;
            LARGE_INTEGER counter;

            HighPerformanceCounterInfo() : frequency(), counter() {}

            HighPerformanceCounterInfo(bool performInitLogic) {
                if (performInitLogic) {
                    QueryPerformanceFrequency(&frequency);
                    QueryPerformanceCounter(&counter);
                }
                else
                {
                    frequency = LARGE_INTEGER();
                    counter = LARGE_INTEGER();
                }
            }

            friend std::ostream& operator<<(std::ostream& os, const HighPerformanceCounterInfo& counterInfo) {
                os << "HPC: " << counterInfo.counter.QuadPart << " / " << counterInfo.frequency.QuadPart;
                return os;
            }
        };

        struct CoreInfo {
            int logicalProcessorId;
            long long processorTick;

            CoreInfo() : logicalProcessorId(), processorTick() {}

            CoreInfo(bool performInitLogic) {
                if (performInitLogic) {
                    processorTick = __rdtsc();
                    logicalProcessorId = GetCurrentProcessorNumber();
                }
                else {

                }
            }

            friend std::ostream& operator<<(std::ostream& os, const CoreInfo& coreInfo) {
                os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
                return os;
            }
        };

        struct RTC {
            std::chrono::system_clock::time_point timestamp;

            RTC() : timestamp() {};

            RTC(bool performInitLogic) {
                if (!performInitLogic) return;
                timestamp = std::chrono::system_clock::now();
            }

            friend std::ostream& operator<<(std::ostream& os, const RTC& rtc) {
                os << "RTC: " << rtc.timestamp;
                return os;
            }
        };

        struct SystemInfo {
            CoreInfo coreInfo;
            HighPerformanceCounterInfo highPerformanceCounterInfo;
            RTC rtc;

            bool DoPerformanceInfo;
            bool DoCoreInfo;
            bool DoRTC;


            friend std::ostream& operator<<(std::ostream& os, const SystemInfo& systemInfo) {
                if (systemInfo.DoCoreInfo)
                {
                    os << systemInfo.coreInfo;
                    os << " -- ";
                }
                if (systemInfo.DoPerformanceInfo) {
                    os << systemInfo.highPerformanceCounterInfo;
                    os << " -- ";
                }
                if (systemInfo.DoRTC)
                {
                    os << systemInfo.rtc;
                }

                return os;
            }

            SystemInfo(bool doCoreInfo, bool doPerformanceInfo, bool doRTC) :
                coreInfo(doCoreInfo),
                highPerformanceCounterInfo(doPerformanceInfo),
                rtc(doRTC),
                DoCoreInfo(doCoreInfo),
                DoPerformanceInfo(doPerformanceInfo),
                DoRTC(doRTC) {

            }
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
    };
    
    std::string LPCWSTRToString(LPCWSTR lpcwstr);


    template<typename... Args>
    std::string_view convertToStringView(const std::string& str, Args&&... args) {
        std::stringstream ss;
        (ss << ... << std::forward<Args>(args));
        return ss.str();
    };


}
#endif
 