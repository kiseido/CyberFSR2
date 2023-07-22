#include "pch.h"
#include "CyberTypes.h"

#ifndef CyberLOGGER_H
#define CyberLOGGER_H

#include <queue>

#include <fstream>

namespace CyberLogger {
 
    class Logger {
    public:
        ~Logger();
        Logger();
        Logger(const LPCWSTR fileName, const bool doPerformanceInfo, const bool doCoreInfo, const bool doRTC);
        void start();
        void stop();

        void logVerboseInfo( const std::string_view& functionName, CyString message);

        void logInfo( const std::string_view& functionName, CyString message);
        void logWarning(const std::string_view& functionName, CyString message);
        void logError(const std::string_view& functionName, CyString message);

    private:


    public:
        template<typename... Args>
        void log(const LogType& logType, const CyString& functionName, Args&&... args) {
            std::wostringstream strStream; 
            variadicLogHelper(strStream, std::forward<Args>(args)...);
            log(logType, functionName, strStream);
        }

        CyString FileName;

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

#endif
