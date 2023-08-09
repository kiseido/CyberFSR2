#include "pch.h"

#ifndef CyberNGX_Utils
#define CyberNGX_Utils

#include <string_view>

namespace CyberUtils {

    // Define the wrapper class template
    template<typename BaseT>
    class Wrapper {
    private:
        BaseT _val;

    public:
        Wrapper() : _val() {}
        Wrapper(const BaseT& val) : _val(val) {}

        Wrapper& operator=(const BaseT& val) {
            _val = val;
            return *this;
        }
        Wrapper& operator=(const Wrapper& other) {
            _val = other._val;
            return *this;
        }

        const BaseT& get() const { return _val; }
        BaseT& get() { return _val; }
        void set(const BaseT& val) { _val = val; }

        BaseT& getBase() { return _val; }
    };

    template <typename BaseT>
    union UnionWrapper {
        BaseT  inner;
        Wrapper<BaseT> wrapped;
    };

    //

    constexpr std::wstring_view GET_PART_AFTER_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
        return name.substr(prefix.size());
    }

    constexpr bool CHECK_STARTS_WITH(const std::wstring_view& prefix, const std::wstring_view& name) {
        return name.compare(0, prefix.size(), prefix) == 0;
    }

    constexpr std::wstring_view TRY_REMOVE_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
        if (CHECK_STARTS_WITH(prefix, name)) {
            return GET_PART_AFTER_PREFIX(prefix, name);
        }
        else {
            return name;
        }
    }

}

#define CyberEnumSwitchHelperOStream(stream, prefix, name) \
    case name: { \
        stream << CyberUtils::TRY_REMOVE_PREFIX(L#prefix, L#name); \
        break;\
    }

#define CyberEnumSwitchHelperReturner(prefix, name) \
    case name: { \
        return CyberUtils::TRY_REMOVE_PREFIX(L#prefix, L#name); \
    }

#endif