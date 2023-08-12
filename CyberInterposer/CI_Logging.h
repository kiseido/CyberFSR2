#include "pch.h"

#ifndef CyInt_CyberFSRLogging
#define CyInt_CyberFSRLogging

namespace CyberInterposer {
    extern CyberLogger::Logger logger;
}


#define CyberLOG() CyberInterposer::logger.logVerboseInfo( __FUNCTIONW__, L"")

#define CyberLOGvi(...) \
    { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberInterposer::logger.logVerboseInfo( __FUNCTIONW__, str); \
    }

#define CyberLOGi(...) \
    { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberInterposer::logger.logInfo( __FUNCTIONW__, str); \
    }

#define CyberLOGw(...) \
    { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberInterposer::logger.logWarning( __FUNCTIONW__, str); \
    }

#define CyberLOGe(...) \
    { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberInterposer::logger.logError( __FUNCTIONW__, str); \
    }

#define CyberLogLots(...) \
    { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberInterposer::logger.logVerboseInfo( __FUNCTIONW__, str); \
    }


#define CyberLogArgs(...) CyberLOGvi(__VA_ARGS__)

#endif