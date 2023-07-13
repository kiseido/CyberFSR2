#ifndef LOGGER_H
#define LOGGER_H


#define CyberLOG() CyberFSR::Logger::log(CyberFSR::Logger::LogType::INFO_t, __func__, "");

#define CyberLOGy(stringy) CyberFSR::Logger::log(CyberFSR::Logger::LogType::INFO_t, __func__, stringy)

#define CyberLogLots(...) \
    do { \
        std::string_view stream_sv = CyberFSR::convertToStringView(__VA_ARGS__);; \
        CyberFSR::Logger::log(CyberFSR::Logger::LogType::INFO_t, __func__, stream_sv); \
    } while (false)

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

    template<typename... Args>
    std::string_view convertToStringView(const std::string& str, Args&&... args) {
        std::stringstream ss;
        (ss << ... << std::forward<Args>(args));
        return ss.str();;
    }
}
#endif
 