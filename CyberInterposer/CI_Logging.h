#include "pch.h"

#ifndef CyInt_CyberFSRLogging
#define CyInt_CyberFSRLogging

namespace CyberInterposer {
    extern CyberLogger::Logger logger;
}


#define CyberLOG() CyberInterposer::logger.logVerboseInfo(__func__, L"")

#define CyberLOGvi(...) \
    { \
        std::wstring str = CyberTypes::concat_arguments(__VA_ARGS__); \
        CyberInterposer::logger.logVerboseInfo(__func__, str); \
    }

#define CyberLOGi(...) \
    { \
        std::wstring str = CyberTypes::concat_arguments(__VA_ARGS__); \
        CyberInterposer::logger.logInfo(__func__, str); \
    }

#define CyberLOGw(...) \
    { \
        std::wstring str = CyberTypes::concat_arguments(__VA_ARGS__); \
        CyberInterposer::logger.logWarning(__func__, str); \
    }

#define CyberLOGe(...) \
    { \
        std::wstring str = CyberTypes::concat_arguments(__VA_ARGS__); \
        CyberInterposer::logger.logError(__func__, str); \
    }

#define CyberLogLots(...) \
    { \
        std::wstring str = CyberTypes::concat_arguments(__VA_ARGS__); \
        CyberInterposer::logger.logVerboseInfo(__func__, str); \
    }


#define CyberLogArgs(...) CyberLOGvi(CyberTypes::output_arguments(__VA_ARGS__))

#endif