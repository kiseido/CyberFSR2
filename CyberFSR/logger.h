#ifndef LOGGER_H
#define LOGGER_H



#define CyberLOG() \
    do { \
        uint64_t errorInfo = 0; \
        CyberFSR::Logger::log(CyberFSR::Logger::LogType::INFO_t, __func__, "", errorInfo); \
    } while (false)

#define CyberLOGy(stringy) CyberFSR::Logger::log(CyberFSR::Logger::LogType::INFO_t, __func__, stringy, 0)

namespace CyberFSR {

    class Logger {
    public:
        enum LogType {
            CLEAN,      // Represents a clean state of the logger
            INFO_t,     // Represents an information log type
            WARNING_t,  // Represents a warning log type
            ERROR_t,    // Represents an error log type
            BAD         // Represents an error occured inide the logger somehow, don't use it
        };

        static void init();
        static void cleanup();
        static void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const std::string& dynamicInfo, const uint64_t& errorInfo);
        static void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo, const uint64_t& errorInfo);
        static void log(const LogType& logType, const std::string_view& functionName, const std::string_view& staticInfo);
        static void log(const LogType& logType, const std::string_view& functionName, const uint64_t& errorInfo);
        static void log(const LogType& logType, const std::string_view& functionName);
    };
}

#endif
