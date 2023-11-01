#include "pch.h"

#include "CyberNGX_Strings.h"

#include <unordered_map>

namespace CyberNGX::NGX_StringsHelper {

    constexpr StringsArray MacroStrings_macroname = { CyberNGX_Strings_Macros(CyberNGX_Strings_MacroNameString) };
    constexpr StringsArray MacroStrings_macrocontent = { CyberNGX_Strings_Macros(CyberNGX_Strings_MacroContentsString) };

    constexpr ValuePairArray MacroStrings_macronamepairs = { CyberNGX_Strings_Macros(CyberNGX_Strings_NameEnumPair) };
    constexpr ValuePairArray MacroStrings_macrocontentpairs = { CyberNGX_Strings_Macros(CyberNGX_Strings_ContentEnumPair) };

    consteval bool compareValuePairs(const ValuePair& a, const ValuePair& b) {
        return a.first < b.first;
    }

    consteval ValuePairArray sortValuePairArray(const ValuePairArray& arr) {
        ValuePairArray sortedArray = arr;
        std::sort(sortedArray.begin(), sortedArray.end(), compareValuePairs);
        return sortedArray;
    }

    constexpr ValuePairArray sortedNamePairs = sortValuePairArray(MacroStrings_macronamepairs);
    constexpr ValuePairArray sortedContentPairs = sortValuePairArray(MacroStrings_macrocontentpairs);

    using MacroStrings_enum = NGX_StringsHelper::MacroStrings_enum;

    constexpr size_t findLongestStringLength(const ValuePairArray& pairs) {
        size_t maxLength = 0;
        for (const auto& pair : pairs) {
            if (maxLength < pair.first.length())
                maxLength = pair.first.length();
        }
        return maxLength;
    }

    constexpr size_t sortedNamePairsHighestCharCount = findLongestStringLength(sortedNamePairs);
    constexpr size_t sortedContentPairsHighestCharCount = findLongestStringLength(sortedContentPairs);

    inline const std::unordered_map<std::string_view, MacroStrings_enum> names(sortedNamePairs.begin(), sortedNamePairs.end());
    inline const std::unordered_map<std::string_view, MacroStrings_enum> content(sortedContentPairs.begin(), sortedContentPairs.end());

    MacroStrings_enum StringConverter::getEnumFromName(const std::string_view& chars) const {
            auto it = names.find(chars);
            if (it != names.end()) {
                return it->second;
            }
            else {
                return MacroStrings_enum::COUNT_enum;
            }
    }

    MacroStrings_enum StringConverter::getEnumFromContent(const std::string_view& chars) const {
        auto it = content.find(chars);
        if (it != content.end()) {
            return it->second;
        }
        else {
            return MacroStrings_enum::COUNT_enum;
        }
    }

    std::string_view StringConverter::getNameFromEnum(MacroStrings_enum value) const {
        if (value >= 0 && value < COUNT_enum) {
            return MacroStrings_macroname[value];
        }
        else {
            return "";
        }
    }

    std::string_view StringConverter::getContentFromEnum(MacroStrings_enum value) const {
        if (value >= 0 && value < COUNT_enum) {
            return MacroStrings_macrocontent[value];
        }
        else {
            return "";
        }
    }
}