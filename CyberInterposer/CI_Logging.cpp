#include "pch.h"
#include "NGX_Interposer.h"
#include "CI_Logging.h"

constexpr bool doPerformanceInfo = false;
constexpr bool doCoreInfo = true;
constexpr bool doRTC = false;

CyberLogger::Logger CyberInterposer::logger(L"CyberInterposer.log", doPerformanceInfo, doCoreInfo, doRTC);
