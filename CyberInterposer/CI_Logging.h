#include "pch.h"

#ifndef CyInt_CyberFSRLogging
#define CyInt_CyberFSRLogging

namespace CyberInterposer {
    extern CyberLogger::Logger logger;
}


#define CyberLOG() CyberInterposer::logger.logVerboseInfo(__func__, L"")

#define CyberLOGvi(...) \
    { \
        std::wstringstream logStream;\
        logStream << CyberTypes::convertToString(__VA_ARGS__);\
        auto string = logStream.str();\
        CyberInterposer::logger.logVerboseInfo(__func__, string); \
    }

#define CyberLOGi(...) \
    { \
        std::wstringstream logStream;\
        logStream << CyberTypes::convertToString(__VA_ARGS__);\
        auto string = logStream.str();\
        CyberInterposer::logger.logInfo(__func__, string); \
    }

#define CyberLOGw(...) \
    { \
        std::wstringstream logStream;\
        logStream << CyberTypes::convertToString(__VA_ARGS__);\
        auto string = logStream.str();\
        CyberInterposer::logger.logWarning(__func__, string); \
    }

#define CyberLOGe(...) \
    { \
        std::wstringstream logStream;\
        logStream << CyberTypes::convertToString(__VA_ARGS__);\
        auto string = logStream.str();\
        CyberInterposer::logger.logError(__func__, string); \
    }

#define CyberLogLots(...) \
    { \
        std::wstring stream_sv = CyberTypes::convertToString(__VA_ARGS__); \
        CyberInterposer::logger.logVerboseInfo(__func__, stream_sv); \
    }


#define CyberLogArgs(...) CyberLOGvi(__VA_ARGS__)

#endif