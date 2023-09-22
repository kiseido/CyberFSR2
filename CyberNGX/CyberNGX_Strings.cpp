#include "pch.h"

#include "CyberNGX_Strings.h"


#include <unordered_map>

void NGX_Strings::NGX_String_Converter::populate_maps() {
    initstatus = warming;

    for (std::size_t i = 0; i < COUNT_enum; ++i) {
        map_macroname_to_enum[NGX_Strings_macroname[i]] = static_cast<NGX_Strings::MacroStrings_enum>(i);
    }
    for (std::size_t i = 0; i < COUNT_enum; ++i) {
        map_macrocontent_to_enum[NGX_Strings_macrocontent[i]] = static_cast<NGX_Strings::MacroStrings_enum>(i);
    }

    initstatus = hot;
}

NGX_Strings::NGX_String_Converter::NGX_String_Converter() {
    populate_maps();
}

NGX_Strings::MacroStrings_enum NGX_Strings::NGX_String_Converter::getEnumFromMacroName(const std::string_view& chars) {
    auto found = map_macroname_to_enum.find(chars);
    if (found != map_macroname_to_enum.end()) {
        return found->second;
    }
    return COUNT_enum;  // Not found
}

NGX_Strings::MacroStrings_enum NGX_Strings::NGX_String_Converter::getEnumFromMacroContents(const std::string_view& chars) {
    auto found = map_macrocontent_to_enum.find(chars);
    if (found != map_macrocontent_to_enum.end()) {
        return found->second;
    }
    return COUNT_enum;  // Not found
}

std::string_view NGX_Strings::NGX_String_Converter::getMacroNameFromEnum(MacroStrings_enum chars) {
    if (chars >= 0 && chars < COUNT_enum) {
        return NGX_Strings_macroname[chars];
    }
    return ""; // Invalid enum value
}

std::string_view NGX_Strings::NGX_String_Converter::getMacroContentFromEnum(MacroStrings_enum chars) {
    if (chars >= 0 && chars < COUNT_enum) {
        return NGX_Strings_macrocontent[chars];
    }
    return ""; // Invalid enum value
}
