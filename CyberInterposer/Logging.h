#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging


#define CyberLOG() CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, "")

#define CyberLOGy(stringy) \
    do { \
        std::stringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, string); \
    } while (false)

#define CyberLogLots(...) \
    do { \
        std::string_view stream_sv = CyberLogger::convertToStringView(__VA_ARGS__); \
        CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, stream_sv); \
    } while (false)

#endif

#define CyberLogArgs(stringy) \
    do { \
        std::stringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, string); \
    } while (false)