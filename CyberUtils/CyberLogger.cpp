#include "pch.h"

#include "CyberLogger.h"

#include <string_view>
#include <iostream>
#include <sstream>
#include <string>

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
    : stopWritingThread(false), logQueue(), queueMutex(), queueCondVar(), writingThread() {
    DoPerformanceInfo = false;
    DoCoreInfo = false;
    DoRTC = false;
}

CyberLogger::Logger::Logger(const LPCWSTR& fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC)
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
        writingThread.detach();
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
    std::wofstream logFile;

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

            {
                std::wstringstream stream;
                stream << entry;
                recallWindow.InsertLine(stream.str());
            }

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

CyberLogger::TextRecallWindow::TextRecallWindow() : LastLineOverwriteIndex(0), NextLineOverwriteIndex(0) {
    std::memset(buffer, 0, sizeof(buffer));
    std::memset(callbacks, 0, sizeof(callbacks));

    for (auto& line : lines) {
        line = std::wstring_view();
    }
}

void CyberLogger::TextRecallWindow::InsertLine(const std::wstring& line) {
    std::lock_guard<std::mutex> lock(accessMutex);

    const SIZE_T length = std::min(MAX_CHAR_PER_LINE - 1, line.length());

    const SIZE_T lengthLeft = MAX_CHAR_PER_LINE - length;

    const SIZE_T lastbufferIndex = LastLineOverwriteIndex * MAX_CHAR_PER_LINE;
    const SIZE_T currentbufferIndex = NextLineOverwriteIndex * MAX_CHAR_PER_LINE;

    const auto CurrentBufferPointer = &buffer[currentbufferIndex];

    const auto oldUsedSize = lines[NextLineOverwriteIndex].length();

    if (oldUsedSize > length) {
        const auto remnantCount = oldUsedSize - length;
        const auto remnantPointer = CurrentBufferPointer + length;
        std::wmemset(remnantPointer, 0, remnantCount);
    }

    // Copy the new line into the buffer
    std::wmemcpy(CurrentBufferPointer, line.c_str(), length);

    CurrentBufferPointer[length] = L'\n';

    // Update the string_view to point to the new line in the buffer
    lines[NextLineOverwriteIndex] = std::wstring_view(CurrentBufferPointer, length);

    // Update the indices for the next insert
    LastLineOverwriteIndex = NextLineOverwriteIndex;
    NextLineOverwriteIndex = (NextLineOverwriteIndex + 1) % MAX_LINE_COUNT;

    for (int i = 0; i < MAX_CALLBACKS; i++) {
        auto& callback = callbacks[i];
        if (callback != nullptr) {
            callback(lines[NextLineOverwriteIndex], LastLineOverwriteIndex, length);
        }
        else
            break;
    }
}


std::vector<std::wstring> CyberLogger::TextRecallWindow::GetLines() const {
    std::lock_guard<std::mutex> lock(accessMutex);

    std::vector<std::wstring> result(MAX_LINE_COUNT);
    for (int i = 0; i < MAX_LINE_COUNT; i++) {
        if (!lines[i].empty()) {
            result[i] = lines[i];
        }
    }
    return result;
}

bool CyberLogger::TextRecallWindow::addListener(StringUpdateCallback newCallback) {
    if (newCallback == 0)
        return false;

    std::lock_guard<std::mutex> lock(accessMutex);

    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (callbacks[i] == nullptr) {
            callbacks[i] = newCallback;
            return true;
        }
    }
    return false;
}

bool CyberLogger::TextRecallWindow::removeListener(StringUpdateCallback callbackToRemove) {
    if (!callbackToRemove)
        return false;  // Invalid callback provided

    std::lock_guard<std::mutex> lock(accessMutex);

    bool removed = false;

    // Iterate through the callback array
    for (int removalIndex = 0; removalIndex < MAX_CALLBACKS; removalIndex++) {
        if (callbacks[removalIndex] == callbackToRemove) {
            // Found the callback to remove
            callbacks[removalIndex] = 0;
            removed = true;

            // Bubble the empty slot down by swapping with the next non-empty slot
            for (int bubbleIndex = removalIndex + 1; bubbleIndex < MAX_CALLBACKS; bubbleIndex++) {

                auto*& current = callbacks[bubbleIndex-1];
                auto*& next = callbacks[bubbleIndex];
                if (next) {
                    current = next;

                }
                else {
                    current = 0;
                }
            }
        }
    }

    return removed;
}
