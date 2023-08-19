#include "pch.h"

#ifndef CyberFSRLogging
#define CyberFSRLogging



//#define doCFSRLogging

#ifdef doCFSRLogging

namespace CyberFSR {
    extern CyberLogger::Logger logger;
}

#define CyberLOG() CyberFSR::logger.logVerboseInfo(__FUNCTIONW__, L"")

#define CyberLOGvi(...) \
    do { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberFSR::logger.logVerboseInfo(__FUNCTIONW__, str); \
    } while (false)

#define CyberLOGi(...) \
    do { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberFSR::logger.logInfo(__FUNCTIONW__, str); \
    } while (false)

#define CyberLOGw(...) \
    do { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberFSR::logger.logWarning(__FUNCTIONW__, str); \
    } while (false)

#define CyberLOGe(...) \
    do { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberFSR::logger.logError(__FUNCTIONW__, str); \
    } while (false)

#define CyberLogLots(...) \
    do { \
        std::wstring str = stringify_args(__VA_ARGS__); \
        CyberFSR::logger.logVerboseInfo(__FUNCTIONW__, str); \
    } while (false)


#define CyberLogArgs(...) CyberLOGvi(__VA_ARGS__)

#endif // doCFSRLogging


#ifndef doCFSRLogging

#define CyberLOG() 

#define CyberLOGvi(...) 

#define CyberLOGi(...) 

#define CyberLOGw(...) 

#define CyberLOGe(...) 

#define CyberLogLots(...) 


#define CyberLogArgs(...) 

#endif // doCFSRLogging

#endif