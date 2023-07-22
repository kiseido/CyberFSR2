#include "pch.h"
#include <map>

#ifndef CyberTypes_H
#define CyberTypes_H


namespace CyberLogger {
    template<typename T1>
    T1& variadicLogHelper(T1& os) {
        return os;
    }

    template<typename T1, typename T2>
    T1& variadicLogHelper(T1& os, const T2& str) {
        os << str;
        return os;
    }

    template<typename T1, typename T2, typename... Args>
    T1& variadicLogHelper(T1& os, const T2& str, Args&&... args) {
        os << str;
        variadicLogHelper(os, std::forward<Args>(args)...);
        return os;
    }

    template<typename... Args>
    std::wstring convertToString(Args&&... args) {
        std::wostringstream  ss;
        variadicLogHelper(ss, std::forward<Args>(args)...);
        return ss.str();
    };

    std::wstring stringToWstring(const std::string_view& str);

    class CyString : public std::wstring {
    public:
        CyString() : std::wstring() {}
        CyString(const std::wstring& wstr) : std::wstring(wstr) {}
        CyString(const std::string& str) : std::wstring(stringToWstring(str)) {}
        CyString(const std::wstring_view& wview) : std::wstring(wview.data(), wview.length()) {}
        CyString(const std::string_view& view) : std::wstring(stringToWstring(view)) {}
        CyString(const char* cstr) : std::wstring(stringToWstring(cstr)) {}
        CyString(const wchar_t* wcstr) : std::wstring(wcstr) {}


        CyString operator+(const CyString& other) const {
            return CyString(static_cast<const std::wstring&>(*this) + static_cast<const std::wstring&>(other));
        }

    };

    enum LoggerStatus {
        Fresh,
        Starting,
        Running,
        Stopping,
        Stopped
    };

    struct StatusContainer {
        LoggerStatus status;
        std::mutex statusLock;

        StatusContainer();
    };

    enum LogType {
        CLEAN,      // Represents a clean state of the logger
        INFO_t,     // Represents an information log type
        INFO_VERBOSE_t,     // Represents an information log type
        WARNING_t,  // Represents a warning log type
        ERROR_t,    // Represents an error log type
        BAD         // Represents an error occurred inside the logger somehow, don't use it
    };

    struct HighPerformanceCounterInfo {
        LARGE_INTEGER frequency;
        LARGE_INTEGER counter;

        HighPerformanceCounterInfo();
        HighPerformanceCounterInfo(bool performInitLogic);
    };

    struct CoreInfo {
        int logicalProcessorId;
        long long processorTick;

        CoreInfo();
        CoreInfo(bool performInitLogic);
    };

    struct RTC {
        std::chrono::system_clock::time_point timestamp;

        RTC();
        RTC(bool performInitLogic);
    };

    struct SystemInfo {
        CoreInfo coreInfo;
        HighPerformanceCounterInfo highPerformanceCounterInfo;
        RTC rtc;

        bool DoPerformanceInfo;
        bool DoCoreInfo;
        bool DoRTC;

        SystemInfo(bool doCoreInfo, bool doPerformanceInfo, bool doRTC);
    };

    struct LogEntry {
        LogType type;
        SystemInfo hardware_info;
        CyString message;
        std::string_view function;

        LogEntry(LogType, SystemInfo, std::string_view, CyString);
    };


    std::string_view getLogTypeName(LogType logType);

}



#endif