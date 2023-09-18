#include "pch.h"

#include "CyberNGX_Strings.h"


#include <unordered_map>

void NGX_Strings::NGX_Enum_Strings::populate_maps() {
    initstatus = warming;

    for (std::size_t i = 0; i < COUNT_enum; ++i) {
        map_macroname_to_enum[NGX_Strings_macroname[i]] = static_cast<NGX_Strings_enum>(i);
    }
    for (std::size_t i = 0; i < COUNT_enum; ++i) {
        map_macrocontent_to_enum[NGX_Strings_macrocontent[i]] = static_cast<NGX_Strings_enum>(i);
    }

    initstatus = hot;
}

NGX_Strings::NGX_Enum_Strings::NGX_Enum_Strings() {
    populate_maps();
}

NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum NGX_Strings::NGX_Enum_Strings::getEnumFromMacroName(const std::string_view& value) {
    auto found = map_macroname_to_enum.find(value);
    if (found != map_macroname_to_enum.end()) {
        return found->second;
    }
    return COUNT_enum;  // Not found
}

NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum NGX_Strings::NGX_Enum_Strings::getEnumFromMacroContents(const std::string_view& value) {
    auto found = map_macrocontent_to_enum.find(value);
    if (found != map_macrocontent_to_enum.end()) {
        return found->second;
    }
    return COUNT_enum;  // Not found
}

std::string_view NGX_Strings::NGX_Enum_Strings::getMacroNameFromEnum(NGX_Strings_enum value) {
    if (value >= 0 && value < COUNT_enum) {
        return NGX_Strings_macroname[value];
    }
    return ""; // Invalid enum value
}

std::string_view NGX_Strings::NGX_Enum_Strings::getMacroContentFromEnum(NGX_Strings_enum value) {
    if (value >= 0 && value < COUNT_enum) {
        return NGX_Strings_macrocontent[value];
    }
    return ""; // Invalid enum value
}
