#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging



namespace CyberFSR{
    static CyberLogger::Logger logger;
}


#define CyberLOG() CyberFSR::logger.log(CyberLogger::LogType::INFO_t, __func__, "")

#define CyberLOGy(stringy) CyberFSR::logger.log(CyberLogger::LogType::INFO_t, __func__, std::string(stringy))

#define CyberLogLots(...) \
    do { \
        std::string_view stream_sv = CyberLogger::convertToStringView(__VA_ARGS__); \
        CyberFSR::logger.log(CyberLogger::LogType::INFO_t, __func__, stream_sv); \
    } while (false)

#endif