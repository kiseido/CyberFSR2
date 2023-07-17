#include "pch.h"
#include "CyberLogger.h"

namespace CyberLogger {

    HighPerformanceCounterInfo::HighPerformanceCounterInfo() : frequency(), counter() {}

    HighPerformanceCounterInfo::HighPerformanceCounterInfo(bool performInitLogic) {
        if (performInitLogic) {
            QueryPerformanceFrequency(&frequency);
            QueryPerformanceCounter(&counter);
        }
        else {
            frequency = LARGE_INTEGER();
            counter = LARGE_INTEGER();
        }
    }

    std::ostream& operator<<(std::ostream& os, const HighPerformanceCounterInfo& counterInfo) {
        os << "HPC: " << counterInfo.counter.QuadPart << " / " << counterInfo.frequency.QuadPart;
        return os;
    }

    CoreInfo::CoreInfo() : logicalProcessorId(), processorTick() {}

    CoreInfo::CoreInfo(bool performInitLogic) {
        if (performInitLogic) {
            processorTick = __rdtsc();
            logicalProcessorId = GetCurrentProcessorNumber();
        }
        else {
            processorTick = 0;
            logicalProcessorId = 0;
        }
    }

    StatusContainer::StatusContainer() : status(Fresh)
    {
    }

    std::ostream& operator<<(std::ostream& os, const CoreInfo& coreInfo) {
        os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
        return os;
    }

    RTC::RTC() : timestamp() {}

    RTC::RTC(bool performInitLogic) {
        if (!performInitLogic) return;
        timestamp = std::chrono::system_clock::now();
    }

    std::ostream& operator<<(std::ostream& os, const RTC& rtc) {
        os << "RTC: " << rtc.timestamp;
        return os;
    }

    SystemInfo::SystemInfo(bool doCoreInfo, bool doPerformanceInfo, bool doRTC)
        : coreInfo(doCoreInfo), highPerformanceCounterInfo(doPerformanceInfo), rtc(doRTC),
        DoCoreInfo(doCoreInfo), DoPerformanceInfo(doPerformanceInfo), DoRTC(doRTC) {}

    std::ostream& operator<<(std::ostream& os, const SystemInfo& systemInfo) {
        if (systemInfo.DoCoreInfo) {
            os << systemInfo.coreInfo;
            os << " -- ";
        }
        if (systemInfo.DoPerformanceInfo) {
            os << systemInfo.highPerformanceCounterInfo;
            os << " -- ";
        }
        if (systemInfo.DoRTC) {
            os << systemInfo.rtc;
        }
        return os;
    }

    Logger::Logger()
        : stopWritingThread(false), logQueue(), queueMutex(), queueCondVar(), writingThread(), logFile() {
        DoPerformanceInfo = false;
        DoCoreInfo = false;
        DoRTC = false;
    }

    Logger::~Logger() {
        stop();
    }

    void Logger::start(const LPCWSTR fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC) {

        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        bool doStart = false;
        {
            std::lock_guard<std::mutex> lock(LoggerStatus.statusLock);

            if (LoggerStatus.status == Fresh || LoggerStatus.status == Stopped) {
                doStart = true;
                LoggerStatus.status = Starting;
            }
        }

        if (!doStart) return;

        DoPerformanceInfo = doPerformanceInfo;
        DoCoreInfo = doCoreInfo;
        DoRTC = doRTC;
        FileName = LPCWSTRToString(fileName);

        std::stringstream logStream;
        logStream << "CyberLogger init" << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        if (!writingThread.joinable()) {
            stopWritingThread = false;
            writingThread = std::thread(&Logger::WritingThreadFunction, this);
        }
    }

    void Logger::stop() {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        bool doStop = false;
        {
            std::lock_guard<std::mutex> lock(LoggerStatus.statusLock);

            if (LoggerStatus.status == Starting || LoggerStatus.status == Running) {
                doStop = true;
                LoggerStatus.status = Stopping;
            }
        }
        if (!doStop) return;

        std::stringstream logStream;
        logStream << "CyberLogger Stop" << '\n';
        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
        stopWritingThread.store(true);

        writingThread.join();
        {
            std::lock_guard<std::mutex> lock(LoggerStatus.statusLock);
            LoggerStatus.status = Stopped;
        }
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo, bool doPerfInfo) {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        std::stringstream logStream;

        logStream << functionName << " - " << staticInfo << " - " << dynamicInfo << " - " << errorInfo << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo, bool doPerfInfo) {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        std::stringstream logStream;
        logStream << functionName << " - " << staticInfo << " - " << errorInfo << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, bool doPerfInfo) {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        std::stringstream logStream;
        logStream << functionName << " - " << staticInfo << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo, bool doPerfInfo) {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        std::stringstream logStream;
        logStream << functionName << " - " << errorInfo << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName, bool doPerfInfo) {
        SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

        std::stringstream logStream;
        logStream << functionName << '\n';

        auto string = logStream.str();

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            logQueue.push({ perfInfo, string });
        }

        queueCondVar.notify_one();
    }

    void Logger::WritingThreadFunction() {
        if (!logFile.is_open())
            logFile.open("./CyberInterposer.log", std::ios::app);

        {
            std::lock_guard<std::mutex> lock(LoggerStatus.statusLock);
            LoggerStatus.status = Running;
        }

        while (!stopWritingThread) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCondVar.wait(lock, [this] { return !logQueue.empty() || stopWritingThread; });

            while (!logQueue.empty()) {
                lock.lock();
                LogEntry entry = std::move(logQueue.front());
                logQueue.pop();
                lock.unlock();

                logFile << entry.hardwareInfo << " ::: " << entry.message << "\n";
            }
        }

        logFile.close();
    }

    std::string LPCWSTRToString(LPCWSTR lpcwstr) {
        int size = WideCharToMultiByte(CP_UTF8, 0, lpcwstr, -1, nullptr, 0, nullptr, nullptr);
        if (size == 0)
            return ""; // Error occurred

        std::string str(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, lpcwstr, -1, str.data(), size, nullptr, nullptr);

        return str;
    }

}  // namespace CyberLogger
