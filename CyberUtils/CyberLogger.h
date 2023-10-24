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


    class TextRecallWindow {
    public:
        
        typedef void (*StringUpdateCallback)(const std::wstring_view& input, const SIZE_T index, const SIZE_T length);

        TextRecallWindow();

        void InsertLine(const std::wstring& line);

        std::vector<std::wstring> GetLinesChonological() const;
        std::wstring GetLineChonological() const;

        std::vector<std::wstring> GetLines() const;
        std::wstring GetLine(SIZE_T index) const;

        bool addListener(StringUpdateCallback callback);
        bool removeListener(StringUpdateCallback callback);

    private:

        enum CharAllocationSize : UINT8 {
            Base_Multiplier = 50,
            Ultra_Small = 1,
            Small = 2,
            Medium = 4,
            Large = 6,
            Epic = 20,
        };
        static constexpr SIZE_T MAX_CHAR_PER_LINE = Epic * Base_Multiplier;
        static constexpr SIZE_T MAX_LINE_COUNT = Epic * Base_Multiplier;

        static constexpr SIZE_T BUFFER_SIZE = MAX_CHAR_PER_LINE * MAX_LINE_COUNT;

        static constexpr SIZE_T MAX_CALLBACKS = Ultra_Small * Base_Multiplier;

        mutable std::mutex accessMutex;

        wchar_t buffer[BUFFER_SIZE];
        std::wstring_view lines[MAX_LINE_COUNT];
        StringUpdateCallback callbacks[MAX_CALLBACKS];
        int LastLineOverwriteIndex;
        int NextLineOverwriteIndex;
    };

    class Logger {
    public:
        ~Logger();
        Logger();
        Logger(const LPCWSTR& fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC);
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

        TextRecallWindow recallWindow;

    private:

        StatusContainer LoggerStatus;

        std::atomic<bool> stopWritingThread = false;

        std::queue<LogEntry> logQueue;
        std::mutex queueMutex;
        std::condition_variable queueCondVar;

        std::thread writingThread;

        void WritingThreadFunction();
    };

}  // namespace CyberLogger



CyberTypes::CyString_view to_CyString(const CyberLogger::LogType&);
CyberTypes::CyString to_CyString(const CyberLogger::LogEntry&);


std::wostream& operator<<(std::wostream& os, const CyberLogger::LogType& logType);
std::wostream& operator<<(std::wostream& os, const CyberLogger::LogEntry& entry);