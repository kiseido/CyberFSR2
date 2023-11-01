#pragma once

#include "CyberMacro.h"

namespace CyberNGX::NGX_StringsHelper {

    enum MacroStrings_enum { CyberNGX_Strings_Macros(CyberNGX_Strings_ENUM_NAME), COUNT_enum };

    template <typename T>
    using EnumLengthArray = std::array<T, COUNT_enum>;

    using ValuePair = std::pair<std::string_view, MacroStrings_enum>;

    using StringsArray = EnumLengthArray<std::string_view>;
    using ValuePairArray = EnumLengthArray<ValuePair>;

    struct StringConverter {
        MacroStrings_enum getEnumFromName(const std::string_view& chars) const;
        MacroStrings_enum getEnumFromContent(const std::string_view& chars) const;
        std::string_view getNameFromEnum(MacroStrings_enum value) const;
        std::string_view getContentFromEnum(MacroStrings_enum value) const;
    };
}

namespace CyberNGX {
    inline const NGX_StringsHelper::StringConverter StringsConverter;
}