#include "pch.h"
#include "Logger.h"

#include <iostream>
#include <limits>

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__linux__)
#include <sched.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#include <iostream>
#include <limits>
#include <array>
#include <thread>
#include <vector>
#include <fstream>
#include <mutex>
#include <list>
#include <chrono>

namespace LowLatencyLogger {

    // Constants
    constexpr int LOGS_PER_BUFFER = 256;
    constexpr int BUFFER_COUNT = 1000;
    constexpr int DEFAULT_PREALLOCATED_LIST_LENGTH = 10;
    constexpr std::string_view DEFAULT_LOG_FILE = "debug.log";
    constexpr size_t INVALID_CORE_ID = std::numeric_limits<size_t>::max();
    const std::string_view BLANK_STRVIEW = "";
    const std::string BLANK_STRING = "";

    // Stats
    std::atomic<size_t> cleanedNodeCount(0);
    std::atomic<size_t> claimedNodeCount(0);

    // Forward declarations
    struct LogEntry;
    enum class BufferState;
    struct LogBuffer;
    struct LinkedListNode;

    class LogBufferPool {
    private:
        static std::array<LinkedListNode, BUFFER_COUNT> bufferPool;
        static std::array<bool, BUFFER_COUNT> nodeAvailability;  // Array to track node availability

    public:
        static void init();
        static LinkedListNode* getNextAvailableNode(int& startIndex);
        static void releaseNode(LinkedListNode* node);
    };

    class CoreListsManager {
    private:
        static std::vector<LinkedListNode*> log_heads;

    public:
        static void init();
        static LinkedListNode* getNodeForCore(const size_t& coreId);
    };

    class Collector {
    private:
        static std::thread collectorThread;
        static bool shouldTerminate;

    public:
        static void init();
        static void cleanup();
        static void run();
    };

    class Saver {
    private:
        static std::thread saverThread;
        static bool shouldTerminate;

    public:
        static void init();
        static void cleanup();
        static void run();
    };

    // Initialize static variables
    std::array<LinkedListNode, BUFFER_COUNT> LogBufferPool::bufferPool;
    std::array<bool, BUFFER_COUNT> LogBufferPool::nodeAvailability;
    std::vector<LinkedListNode*> CoreListsManager::log_heads;
    std::thread Collector::collectorThread;
    bool Collector::shouldTerminate = false;
    std::thread Saver::saverThread;
    bool Saver::shouldTerminate = false;

    // Real-time clock sorted list for collector
    std::list<LogEntry> rtcSortedList;
    std::mutex rtcSortedListMutex;

    void LogBufferPool::init() {
        // Initialize node availability
        nodeAvailability.fill(true);

        // Create initial long list
        LinkedListNode* lastNode = &bufferPool[0];
        for (int i = BUFFER_COUNT - 1; i >= 0; --i) {
            bufferPool[i].next = lastNode;
            lastNode = &bufferPool[i];
        }
    }

    LinkedListNode* LogBufferPool::getNextAvailableNode(int& startIndex) {
        while (startIndex < BUFFER_COUNT && !nodeAvailability[startIndex]) {
            startIndex++;
        }

        if (startIndex >= BUFFER_COUNT) {
            return nullptr;
        }

        cleanedNodeCount++;
        return &bufferPool[startIndex++];
    }

    void LogBufferPool::releaseNode(LinkedListNode* node) {
        if (node != nullptr) {
            nodeAvailability[node - &bufferPool[0]] = true;
        }
    }

    void CoreListsManager::init() {
        const int coreCount = getTotalCoreCount();
        log_heads.resize(coreCount);

        LinkedListNode* cleanList = &LogBufferPool::bufferPool[0];
        for (int i = 0; i < coreCount; ++i) {
            auto newList = extendList(cleanList, DEFAULT_PREALLOCATED_LIST_LENGTH);
            log_heads[i] = newList;
        }
    }

    LinkedListNode* CoreListsManager::getNodeForCore(const size_t& coreId) {
        return log_heads[coreId];
    }

    LinkedListNode* CoreListsManager::getOpenNode(LinkedListNode* const& inputNode) {
        LinkedListNode* outputNode = inputNode;

        while (outputNode->buffer.state.load() != BufferState::OPEN) {
            outputNode = outputNode->next;
        }
        return outputNode;
    }

    LogEntry* CoreListsManager::getOpenLog(LinkedListNode* const& inputNode) {
        LinkedListNode* node = getOpenNode(inputNode);
        LogBuffer& buffer = node->buffer;

        size_t writePos = buffer.writePosition;

        for (size_t i = 0; i < LOGS_PER_BUFFER; ++i) {
            LogEntry& log = buffer.logs[writePos];

            if (log.logType == LogType::CLEAN) {
                buffer.writePosition = (writePos + 1) % LOGS_PER_BUFFER;
                return &log;
            }

            writePos = (writePos + 1) % LOGS_PER_BUFFER;
        }

        return nullptr;  // No clean log found
    }

    void CoreListsManager::cleanNodes(LinkedListNode* node) {
        while (node != nullptr) {
            node->buffer.state.store(BufferState::CLEAN);
            node->buffer.writePosition = 0;
            node->buffer.readPosition = 0;
            for (auto& log : node->buffer.logs) {
                log.logType = LogType::CLEAN;
                log.functionName = BLANK_STRVIEW;
                log.staticInfo = BLANK_STRVIEW;
                log.dynamicInfo = std::nullopt;
                log.errorInfo = 0;
                log.coreTick = 0;
                log.rtcTime = std::chrono::system_clock::time_point();
            }
            node = node->next;
        }
    }

    LinkedListNode* CoreListsManager::extendList(LinkedListNode* oldNode, int nodeCount) {
        LinkedListNode* firstNode = nullptr;
        LinkedListNode* currentNode = nullptr;

        int i = 0;
        currentNode = LogBufferPool::getNextAvailableNode(i);
        if (currentNode == nullptr) {
            std::cerr << "Warning: No clean nodes available." << std::endl;
            return oldNode;
        }

        firstNode = currentNode;

        for (; i < nodeCount; i++) {
            currentNode = LogBufferPool::getNextAvailableNode(i);

            if (currentNode == nullptr) {
                std::cerr << "Warning: Requested more nodes than available. Only " << i << " nodes were claimed."
                    << std::endl;
                break;
            }

            claimedNodeCount++;
            currentNode = currentNode->next;
        }

        if (i < nodeCount) {
            std::cerr << "Warning: Requested more nodes than available. Only " << i << " nodes were claimed."
                << std::endl;
        }

        if (oldNode != nullptr) {
            oldNode->buffer.state.store(BufferState::CLOSED);
            LinkedListNode* tailOldNode = oldNode;
            while (tailOldNode->next != nullptr) {
                tailOldNode = tailOldNode->next;
            }
            tailOldNode->next = firstNode;
            return oldNode;
        }

        return firstNode;
    }

    void Collector::init() {
        shouldTerminate = false;
        collectorThread = std::thread(run);
    }

    void Collector::cleanup() {
        shouldTerminate = true;
        if (collectorThread.joinable()) {
            collectorThread.join();
        }
    }

    void Collector::run() {
        while (!shouldTerminate) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Simulating collector logic
            // Collect logs from open nodes and sort them by RTC time
            std::vector<LogEntry> collectedLogs;
            collectedLogs.reserve(BUFFER_COUNT * LOGS_PER_BUFFER);

            for (LinkedListNode* node : CoreListsManager::log_heads) {
                LinkedListNode* openNode = CoreListsManager::getOpenNode(node);

                while (openNode != nullptr) {
                    LogEntry* log = CoreListsManager::getOpenLog(openNode);

                    if (log != nullptr) {
                        collectedLogs.push_back(*log);
                        openNode->buffer.state.store(BufferState::COLLECTING);
                    }

                    openNode = openNode->next;
                }
            }

            // Sort collected logs by RTC time
            {
                std::lock_guard<std::mutex> lock(rtcSortedListMutex);
                rtcSortedList.insert(rtcSortedList.end(), collectedLogs.begin(), collectedLogs.end());
            }
        }
    }

    void Saver::init() {
        shouldTerminate = false;
        saverThread = std::thread(run);
    }

    void Saver::cleanup() {
        shouldTerminate = true;
        if (saverThread.joinable()) {
            saverThread.join();
        }
    }

    void Saver::run() {
        while (!shouldTerminate) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Simulating saver logic
            // Save logs from the sorted list to file
            std::list<LogEntry> logsToSave;

            {
                std::lock_guard<std::mutex> lock(rtcSortedListMutex);
                logsToSave.swap(rtcSortedList);
            }

            if (!logsToSave.empty()) {
                std::ofstream file(DEFAULT_LOG_FILE.data(), std::ios::app);

                if (file.is_open()) {
                    for (const auto& log : logsToSave) {
                        file << log.logType << ": " << log.functionName << ", " << log.staticInfo << ", "
                            << log.dynamicInfo.value_or("") << ", " << log.errorInfo << ", " << log.coreId << ", "
                            << log.coreTick << ", " << log.rtcTime.time_since_epoch().count() << std::endl;
                    }
                }
                else {
                    std::cerr << "Failed to open log file for saving." << std::endl;
                }
            }
        }
    }

    // LogEntry structure definition
    struct LogEntry {
        // Existing fields
        CyberFSR::Logger::LogType logType;
        std::string_view functionName;
        std::string_view staticInfo;
        std::optional<std::string> dynamicInfo;
        uint64_t errorInfo;
        std::thread::id threadId;
        size_t coreId;
        uint64_t coreTick;
        std::chrono::system_clock::time_point rtcTime;
    };


    // LogBuffer structure definition
    enum class BufferState {
        CLEAN,
        ALLOCATED,
        OPEN,
        CLOSED,
        COLLECTING,
    };

    struct LogBuffer {
        std::atomic<BufferState> state;
        size_t writePosition;
        size_t readPosition;
        std::array<LogEntry, LOGS_PER_BUFFER> logs;

        LogBuffer() : state(BufferState::CLEAN), writePosition(0), readPosition(0), logs{} {}
    };

    // LinkedListNode structure definition
    struct LinkedListNode {
        LogBuffer buffer;
        LinkedListNode* next;

        LinkedListNode() : buffer(), next(nullptr) {}
    };

    size_t getTotalCoreCount() {
        size_t totalCores = 0;

        // Platform-specific code to get the total number of cores
#if defined(_WIN32)
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        totalCores = sysInfo.dwNumberOfProcessors;
#elif defined(__linux__)
        totalCores = static_cast<size_t>(get_nprocs());
#elif defined(__APPLE__)
        int coreCount;
        size_t len = sizeof(coreCount);
        sysctlbyname("hw.logicalcpu", &coreCount, &len, NULL, 0);
        totalCores = static_cast<size_t>(coreCount);
#endif

        return totalCores;
    }

    size_t getCurrentCoreId() {
        size_t coreId = INVALID_CORE_ID;

        // Platform-specific code to get the current core ID
#if defined(_WIN32)
        // On Windows, use GetCurrentProcessorNumber() from Windows API
        coreId = GetCurrentProcessorNumber();
#elif defined(__linux__)
        // On Linux, use sched_getcpu() from sched.h
        coreId = static_cast<size_t>(sched_getcpu());
#elif defined(__APPLE__)
        // On macOS, use sysctl() with CPU affinity information
        int mib[2];
        int cpuId;
        size_t len = sizeof(cpuId);

        mib[0] = CTL_HW;
        mib[1] = HW_CPUSUBTYPE;

        if (sysctl(mib, 2, &cpuId, &len, nullptr, 0) != -1) {
            coreId = static_cast<size_t>(cpuId);
        }
#endif

        return coreId;
    }

}  // namespace LowLatencyLogger

namespace CyberFSR {

    namespace log = LowLatencyLogger;

    void Logger::init() {
        log::LogBufferPool::init();
        log::CoreListsManager::init();
        log::Collector::init();
        log::Saver::init();
    }

    void Logger::cleanup() {
        log::Collector::cleanup();
        log::Saver::cleanup();
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName,
        const std::string_view& staticInfo, const std::string& dynamicInfo,
        const uint64_t& errorInfo) {
        size_t coreId = log::getCurrentCoreId();
        std::thread::id threadId = std::this_thread::get_id();

        LowLatencyLogger::LinkedListNode* coreList = log::CoreListsManager::getNodeForCore(coreId);

        LowLatencyLogger::LinkedListNode* openNode = log::CoreListsManager::getOpenNode(coreList);

        const int writePos = openNode->buffer.writePosition;

        openNode->buffer.writePosition = (writePos + 1) % log::LOGS_PER_BUFFER;

        LowLatencyLogger::LogEntry* log = &(openNode->buffer.logs[writePos]);

        log->logType = logType;
        log->functionName = functionName;
        log->staticInfo = staticInfo;
        log->dynamicInfo = dynamicInfo;
        log->errorInfo = errorInfo;
        log->threadId = threadId;
        log->coreId = coreId;

        // Update core tick and RTC time
        log->coreTick = getCoreTick();  // Custom function to get the core tick value
        log->rtcTime = std::chrono::system_clock::now();
    }


    void Logger::log(const LogType& logType, const std::string_view& functionName,
        const std::string_view& staticInfo, const uint64_t& errorInfo) {
        log(logType, functionName, staticInfo, log::BLANK_STRING, errorInfo);
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName,
        const std::string_view& staticInfo) {
        log(logType, functionName, staticInfo, log::BLANK_STRING, 0);
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName,
        const uint64_t& errorInfo) {
        log(logType, functionName, log::BLANK_STRVIEW, log::BLANK_STRING, errorInfo);
    }

    void Logger::log(const LogType& logType, const std::string_view& functionName) {
        log(logType, functionName, log::BLANK_STRVIEW, log::BLANK_STRING, 0);
    }
}  // namespace CyberFSR
