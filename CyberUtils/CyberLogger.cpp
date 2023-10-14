#include "CyberLogger.h"

using namespace CyberTypes;

CyberTypes::CyString_view CyberLogger::getLogTypeName(const LogType& logType) {

#define CY_MAPPER( name ) name, L#name
    static std::map<LogType, CyberTypes::CyString_view> logTypeNames{
        {CY_MAPPER(CLEAN)},
        {CY_MAPPER(INFO_t)},
        {CY_MAPPER(INFO_VERBOSE_t)},
        {CY_MAPPER(WARNING_t)},
        {CY_MAPPER(ERROR_t)},
        {CY_MAPPER(BAD)}
    };
#undef CY_MAPPER

    return logTypeNames[logType];
}

CyberLogger::Logger::Logger()
    : stopWritingThread(false), logQueue(), queueMutex(), queueCondVar(), writingThread(), logFile() {
    DoPerformanceInfo = false;
    DoCoreInfo = false;
    DoRTC = false;
}

CyberLogger::Logger::Logger(const LPCWSTR& fileName, const bool& doPerformanceInfo, const bool& doCoreInfo, const bool& doRTC)
{
    DoPerformanceInfo = doPerformanceInfo;
    DoCoreInfo = doCoreInfo;
    DoRTC = doRTC;
    FileName = CyString_view(fileName);
    LoggerStatus.status = Fresh;
}

CyberLogger::Logger::~Logger() {
    stop();
}

void CyberLogger::Logger::start()
{
    std::lock_guard<std::mutex> loglock(queueMutex);

    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

    bool doStart = false;
    if (LoggerStatus.status == Fresh || LoggerStatus.status == Stopped) {
        doStart = true;
        LoggerStatus.status = Starting;
    }

    if (!doStart) return;

    std::wstringstream logStream;
    logStream << "CyberLogger init" << '\n';

    auto string = logStream.str();

    logQueue.push({ LogType::INFO_t, perfInfo, __FUNCTIONW__, string });

    if (!writingThread.joinable()) {
        stopWritingThread = false;
        writingThread = std::thread(&Logger::WritingThreadFunction, this);
        //writingThread.detach();
    }
}

void CyberLogger::Logger::stop() {
    std::lock_guard<std::mutex> loglock(queueMutex);

    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);

    bool doStop = false;
    if (LoggerStatus.status == Starting || LoggerStatus.status == Running) {
        doStop = true;
        LoggerStatus.status = Stopping;
    }
    if (!doStop) return;

    std::wstringstream logStream;
    logStream << "CyberLogger Stop" << '\n';
    auto string = logStream.str();

    logQueue.push({ LogType::INFO_t, perfInfo, __FUNCTIONW__, string });

    queueCondVar.notify_one();
    stopWritingThread.store(true);

    writingThread.join();
    LoggerStatus.status = Stopped;
}

void CyberLogger::Logger::WritingThreadFunction() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);

        if (!logFile.is_open())
            logFile.open(FileName, std::ios::app);

        LoggerStatus.status = Running;
    }

    while (!stopWritingThread) {
        std::unique_lock<std::mutex> lock(queueMutex);
        //queueCondVar.wait(lock, [this] { return !logQueue.empty() || stopWritingThread; });

        while (!logQueue.empty()) {
            LogEntry entry = logQueue.front();
            logQueue.pop();
            lock.unlock();

            logFile << entry << "\n";

            logFile.flush();
            lock.lock();
        }
        lock.unlock();
        std::this_thread::yield();
    }

    logFile.close();
}

void CyberLogger::Logger::logVerboseInfo(const CyString_view& functionName, const CyString& message)
{
    if (!doVerbose) return;

    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::INFO_VERBOSE_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logInfo(const CyString_view& functionName, const CyString& message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::INFO_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logWarning(const CyString_view& functionName, const CyString& message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::WARNING_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logError(const CyString_view& functionName, const CyString& message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::ERROR_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}



CyberLogger::StatusContainer::StatusContainer() : status(Fresh) {}

CyberLogger::LogEntry::LogEntry(const LogType& a, const SystemInfo& b, const CyString_view& c, const CyberTypes::CyString& d) : type(a), hardware_info(b), function(c), message(d)
{
}

CyberLogger::LogEntry::LogEntry(const LogEntry& other) : type(other.type), hardware_info(other.hardware_info), function(other.function), message(other.message)
{
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::LogType& logType) {
    os << getLogTypeName(logType);
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::LogEntry& entry) {
    os << "type: " << getLogTypeName(entry.type) << ", ";
    os << "hardware info: " << entry.hardware_info << ", ";
    os << "function: " << entry.function << ", ";
    os << "message: " << entry.message << " ";
    return os;
}

