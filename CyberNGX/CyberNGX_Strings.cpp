#include "pch.h"

#include "CyberNGX_Strings.h"


#include <unordered_map>

namespace CyberNGX::NGX_Strings {
    StringConverter::StringConverter() {
        for (const auto& pair : NGX_StringsHelper::sortedNamePairs) {
            nameToEnumMap.emplace(pair.first, pair.second);
        }

        for (const auto& pair : NGX_StringsHelper::sortedContentPairs) {
            contentToEnumMap.emplace(pair.first, pair.second);
        }
    }

    MacroStrings_enum StringConverter::getEnumFromName(const std::string_view& chars) const {
        auto found = nameToEnumMap.find(chars);
        if (found != nameToEnumMap.end()) {
            return found->second;
        }
        return MacroStrings_enum::COUNT_enum;  // Not found
    }

    MacroStrings_enum StringConverter::getEnumFromContent(const std::string_view& chars) const {
        auto found = contentToEnumMap.find(chars);
        if (found != contentToEnumMap.end()) {
            return found->second;
        }
        return MacroStrings_enum::COUNT_enum;  // Not found
    }

    std::string_view StringConverter::getNameFromEnum(MacroStrings_enum chars) const {
        if (chars >= 0 && chars < MacroStrings_enum::COUNT_enum) {
            return NGX_StringsHelper::MacroStrings_macroname[chars];
        }
        return ""; // Invalid enum value
    }

    std::string_view StringConverter::getContentFromEnum(MacroStrings_enum chars) const {
        if (chars >= 0 && chars < MacroStrings_enum::COUNT_enum) {
            return NGX_StringsHelper::MacroStrings_macrocontent[chars];
        }
        return ""; // Invalid enum value
    }
}


