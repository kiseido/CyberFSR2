#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging

namespace CyberFSR{
    extern CyberLogger::Logger logger;
}


#define CyberLOG() CyberFSR::logger.logVerboseInfo(__func__, L"")

#define CyberLOGvi(stringy) \
    do { \
        std::wstring stream_sv = CyberTypes::convertToString(stringy); \
        CyberFSR::logger.logVerboseInfo(__func__, stream_sv); \
    } while (false)

#define CyberLOGi(stringy) \
    do { \
        std::wstring stream_sv = CyberTypes::convertToString(stringy); \
        CyberFSR::logger.logInfo(__func__, stream_sv); \
    } while (false)

#define CyberLOGw(stringy) \
    do { \
        std::wstring stream_sv = CyberTypes::convertToString(stringy); \
        CyberFSR::logger.logWarning(__func__, stream_sv); \
    } while (false)

#define CyberLOGe(stringy) \
    do { \
        std::wstring stream_sv = CyberTypes::convertToString(stringy); \
        CyberFSR::logger.logError(__func__, stream_sv); \
    } while (false)

#define CyberLogLots(...) \
    do { \
        std::wstring stream_sv = CyberTypes::convertToString(__VA_ARGS__); \
        CyberFSR::logger.logVerboseInfo(__func__, stream_sv); \
    } while (false)


#define CyberLogArgs(...) CyberLOGvi(__VA_ARGS__)

#endif