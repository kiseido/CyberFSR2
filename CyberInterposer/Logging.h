#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging



namespace CyberInterposer {
    static CyberLogger::Logger logger;
}


#define CyberLOG() CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, "")

#define CyberLOGy(stringy) CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, std::string(stringy))

#define CyberLogLots(...) \
    do { \
        std::string_view stream_sv = CyberLogger::convertToStringView(__VA_ARGS__); \
        CyberInterposer::logger.log(CyberLogger::LogType::INFO_t, __func__, stream_sv); \
    } while (false)

#endif