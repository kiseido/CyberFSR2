#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging

namespace CyberFSR{
    extern CyberLogger::Logger logger;
}


#define CyberLOG() CyberFSR::logger.logVerboseInfo(__func__, L"")

#define CyberLOGvi(stringy) \
    do { \
        std::wstringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberFSR::logger.logVerboseInfo(__func__, string); \
    } while (false)

#define CyberLOGi(stringy) \
    do { \
        std::wstringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberFSR::logger.logInfo(__func__, string); \
    } while (false)

#define CyberLOGw(stringy) \
    do { \
        std::wstringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberFSR::logger.logWarning(__func__, string); \
    } while (false)

#define CyberLOGe(stringy) \
    do { \
        std::wstringstream logStream;\
        logStream << stringy;\
        auto string = logStream.str();\
        CyberFSR::logger.logError(__func__, string); \
    } while (false)

#define CyberLogLots(...) \
    do { \
        std::wstring stream_sv = CyberLogger::convertToString(__VA_ARGS__); \
        CyberFSR::logger.logVerboseInfo(__func__, stream_sv); \
    } while (false)


#define CyberLogArgs(...) CyberLOGvi(__VA_ARGS__)

#endif