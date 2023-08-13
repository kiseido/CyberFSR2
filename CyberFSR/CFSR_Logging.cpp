#include "pch.h"
#include "CFSR_Logging.h"

#ifdef doCFSRLogging
CyberLogger::Logger CyberFSR::logger(L"CyberFSR.log", true, true, true);
#endif


//CyberLogger::Logger CyberFSR::logger = CyberLogger::Logger();
