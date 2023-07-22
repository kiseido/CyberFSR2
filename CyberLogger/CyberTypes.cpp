#include "pch.h"
#include "CyberTypes.h"

std::string_view CyberLogger::getLogTypeName(LogType logType) {

#define CY_MAPPER( name ) name, #name
    static std::map<LogType, std::string_view> logTypeNames{
        {CY_MAPPER(CLEAN)},
        {CY_MAPPER(INFO_t)},
        {CY_MAPPER(INFO_VERBOSE_t)},
        {CY_MAPPER(WARNING_t)},
        {CY_MAPPER(ERROR_t)},
        {CY_MAPPER(BAD)}
    };
#undef CY_MAPPER

    return logTypeNames[logType];
}