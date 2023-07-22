#include "pch.h"
#include "CyberLogger.h"
#include "../external/nvngx_dlss_sdk/include/nvsdk_ngx_defs.h"

std::wostream& operator<<(std::wostream& os, const std::string_view& view) {
    os << std::wstring(view.begin(), view.end());
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::HighPerformanceCounterInfo& counterInfo) {
    os << "HPC: " << counterInfo.counter.QuadPart << " / " << counterInfo.frequency.QuadPart;
    return os;
}
std::wostream& operator<<(std::wostream& os, const CyberLogger::CoreInfo& coreInfo) {
    os << "Core: " << coreInfo.logicalProcessorId << " - " << "Tick: " << coreInfo.processorTick;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::RTC& rtc) {
    os << "RTC: " << rtc.timestamp;
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::LogType& logType) {
    os << getLogTypeName(logType);
    return os;
}

std::wostream& operator<<(std::wostream& os, const CyberLogger::SystemInfo& systemInfo) {
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

std::wostream& operator<<(std::wostream& os, const CyberLogger::LogEntry& entry) {
    os << "type: " << entry.type << ", ";
    os << "hardware info: " << entry.hardware_info << ", ";
    os << "function: " << entry.function << ", ";
    os << "message: " << entry.message << " ";
    return os;
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_Version& version) {
    os << (DWORD)version;
    return os;
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_ProjectIdDescription& desc) {
    os << L"Project ID: " << desc.ProjectId << ", ";
    os << L"Engine Type: " << desc.EngineType << ", ";
    os << L"Engine Version: " << desc.EngineVersion;
    return os;
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_Application_Identifier_Type& identifierType) {
    os << L"NVSDK_NGX_Application_Identifier_Type: ";
    switch (identifierType) {
    case NVSDK_NGX_Application_Identifier_Type_Application_Id:
        os << L"Application_Id";
        break;
    case NVSDK_NGX_Application_Identifier_Type_Project_Id:
        os << L"Project_Id";
        break;
    }
    return os;
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_Application_Identifier& identifier) {
    os << L"NVSDK_NGX_Application_Identifier: ";
    os << L"IdentifierType: " << identifier.IdentifierType << L", ";
    if (identifier.IdentifierType == NVSDK_NGX_Application_Identifier_Type_Application_Id) {
        os << L"ApplicationId: " << identifier.v.ApplicationId;
    }
    else if (identifier.IdentifierType == NVSDK_NGX_Application_Identifier_Type_Project_Id) {
        os << L"ProjectDesc: " << identifier.v.ProjectDesc;
    }
    return os;
}

std::wostream& operator<<(std::wostream& os, const NVSDK_NGX_Feature& feature) {
    os << "NVSDK_NGX_Feature: ";
    switch (feature) {
    case NVSDK_NGX_Feature_Reserved0:
        os << "Reserved0";
        break;
    case NVSDK_NGX_Feature_SuperSampling:
        os << "SuperSampling";
        break;
    case NVSDK_NGX_Feature_InPainting:
        os << "InPainting";
        break;
    case NVSDK_NGX_Feature_ImageSuperResolution:
        os << "ImageSuperResolution";
        break;
    case NVSDK_NGX_Feature_SlowMotion:
        os << "SlowMotion";
        break;
    case NVSDK_NGX_Feature_VideoSuperResolution:
        os << "VideoSuperResolution";
        break;
    case NVSDK_NGX_Feature_Reserved1:
        os << "Reserved1";
        break;
    case NVSDK_NGX_Feature_Reserved2:
        os << "Reserved2";
        break;
    case NVSDK_NGX_Feature_Reserved3:
        os << "Reserved3";
        break;
    case NVSDK_NGX_Feature_ImageSignalProcessing:
        os << "ImageSignalProcessing";
        break;
    case NVSDK_NGX_Feature_DeepResolve:
        os << "DeepResolve";
        break;
    case NVSDK_NGX_Feature_FrameGeneration:
        os << "FrameGeneration";
        break;
    case NVSDK_NGX_Feature_DeepDVC:
        os << "DeepDVC";
        break;
    case NVSDK_NGX_Feature_Reserved13:
        os << "Reserved13";
        break;
    case NVSDK_NGX_Feature_Count:
        os << "Count";
        break;
    case NVSDK_NGX_Feature_Reserved_SDK:
        os << "Reserved_SDK";
        break;
    case NVSDK_NGX_Feature_Reserved_Core:
        os << "Reserved_Core";
        break;
    case NVSDK_NGX_Feature_Reserved_Unknown:
        os << "Reserved_Unknown";
        break;
    }
    return os;
}



CyberLogger::HighPerformanceCounterInfo::HighPerformanceCounterInfo() : frequency(), counter() {}

CyberLogger::HighPerformanceCounterInfo::HighPerformanceCounterInfo(bool performInitLogic) {
    if (performInitLogic) {
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
    }
    else {
        frequency = LARGE_INTEGER();
        counter = LARGE_INTEGER();
    }
}

CyberLogger::CoreInfo::CoreInfo() : logicalProcessorId(), processorTick() {}

CyberLogger::CoreInfo::CoreInfo(bool performInitLogic) {
    if (performInitLogic) {
        processorTick = __rdtsc();
        logicalProcessorId = GetCurrentProcessorNumber();
    }
    else {
        processorTick = 0;
        logicalProcessorId = 0;
    }
}

CyberLogger::StatusContainer::StatusContainer() : status(Fresh) {}

CyberLogger::RTC::RTC() : timestamp() {}

CyberLogger::RTC::RTC(bool performInitLogic) {
    if (!performInitLogic) return;
    timestamp = std::chrono::system_clock::now();
}



CyberLogger::SystemInfo::SystemInfo(bool doCoreInfo, bool doPerformanceInfo, bool doRTC)
    : coreInfo(doCoreInfo), highPerformanceCounterInfo(doPerformanceInfo), rtc(doRTC),
    DoCoreInfo(doCoreInfo), DoPerformanceInfo(doPerformanceInfo), DoRTC(doRTC) {}



CyberLogger::Logger::Logger()
    : stopWritingThread(false), logQueue(), queueMutex(), queueCondVar(), writingThread(), logFile() {
    DoPerformanceInfo = false;
    DoCoreInfo = false;
    DoRTC = false;
}

CyberLogger::Logger::Logger(const LPCWSTR fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC)
{
    DoPerformanceInfo = doPerformanceInfo;
    DoCoreInfo = doCoreInfo;
    DoRTC = doRTC;
    FileName = fileName;
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

    logQueue.push({ LogType::INFO_t, perfInfo, __func__, string });

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

    logQueue.push({ LogType::INFO_t, perfInfo, __func__, string });

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


std::wstring CyberLogger::stringToWstring(const std::string_view& str) {
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::vector<wchar_t> wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return std::wstring(wstr.begin(), wstr.end());
}

void CyberLogger::Logger::logVerboseInfo(const std::string_view& functionName, CyString message)
{
    if (!doVerbose) return;

    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::INFO_VERBOSE_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logInfo(const std::string_view& functionName, CyString message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::INFO_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logWarning(const std::string_view& functionName, CyString message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::WARNING_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

void CyberLogger::Logger::logError(const std::string_view& functionName, CyString message)
{
    SystemInfo perfInfo(DoCoreInfo, DoPerformanceInfo, DoRTC);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({ LogType::ERROR_t, perfInfo, functionName, message });
    }
    queueCondVar.notify_one();
}

CyberLogger::LogEntry::LogEntry(LogType a, SystemInfo b, std::string_view c, CyString d) :type(a), hardware_info(b), function(c), message(d)
{
}
