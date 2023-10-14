#include "CyberConfigurationator.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

using AVT = Configurationator::AcceptedValueTypes;

namespace AVTUtils {


    AVT pack(AVT a, AVT b) {
        return static_cast<AVT>(
            static_cast<int>(a) | static_cast<int>(b)
            );
    }

    AVT pack(AVT a, AVT b, AVT c) {
        return static_cast<AVT>(
            static_cast<int>(a) | static_cast<int>(b) | static_cast<int>(c)
            );
    }

    bool contains(AVT value, AVT flag) {
        return (static_cast<int>(value) & static_cast<int>(flag)) != 0;
    }

}
inline AVT operator| (AVT a, AVT b) {
    return static_cast<AVT>(static_cast<int>(a) | static_cast<int>(b));
}

inline AVT& operator|= (AVT& a, AVT b) {
    return a = a | b;
}

inline AVT operator& (AVT a, AVT b) {
    return static_cast<AVT>(static_cast<int>(a) & static_cast<int>(b));
}

inline AVT& operator&= (AVT& a, AVT b) {
    return a = a & b;
}

// Helper function to trim whitespace from a string.
static std::wstring trim(const std::wstring& str) {
    size_t start = str.find_first_not_of(L" \t");
    size_t end = str.find_last_not_of(L" \t");
    return (start == std::wstring::npos) ? L"" : str.substr(start, end - start + 1);
}

Configurationator::ini_value::ini_value(
    value_type value,
    LoadStatus loadStatus
)
    : value(value),
    DefaultValue(value),
    loaded_status(loadStatus),
    Acceptable_Types(AcceptedValueTypes::NotSet),
    Acceptable_Values({}),
    Comments({})
{ }

Configurationator::ini_value::ini_value(
    value_type DefaultValue,
    AcceptedValueTypes AcceptableTypes,
    const std::vector<value_type>& AcceptableValues,
    const std::vector<std::wstring>& Comments
)
    : value(DefaultValue),
    DefaultValue(DefaultValue),
    loaded_status(LoadStatus::Missing),
    Acceptable_Types(AcceptableTypes),
    Acceptable_Values(AcceptableValues),
    Comments(Comments)
{ }

Configurationator::ini_section::ini_section() : std::map<std::wstring, ini_value>(), Comments() {}

Configurationator::ini_section::ini_section(const std::vector<std::wstring>& comments) : std::map<std::wstring, ini_value>(), Comments(comments) {}

Configurationator::ini_section::ini_section(const ini_section& other) : std::map<std::wstring, ini_value>(other), Comments(other.Comments) {}

// Constructor implementation
Configurationator::Configurationator() {
}


void Configurationator::saveToFile(const std::wstring& filename) {
    std::wofstream file(filename);

    if (!file.is_open()) {
        // Handle file opening error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Unable to open file for writing");
    }

    std::wstring serializedData = serialize();
    file << serializedData;

    if (file.fail()) {
        // Handle file writing error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Error writing to file");
    }

    file.close();
}


Configurationator::ini_section& Configurationator::operator[](const std::wstring& key) {
    return configData[key];
}

Configurationator::FileLoadStatus Configurationator::loadFromFile(const std::wstring& filename) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        // Handle file opening error by returning an appropriate status
        return FileLoadStatus::FileNotFound;
    }

    std::wstringstream buffer;
    buffer << file.rdbuf();

    if (!deserialize(buffer.str())) {
        // Handle INI deserialization error by returning an appropriate status
        file.close();
        return FileLoadStatus::DeserializeError;
    }

    file.close();
    return FileLoadStatus::Success;
}

std::wstring Configurationator::serialize() {
    std::wstringstream out;

    for (const auto& [sectionName, sectionData] : configData) {
        out << L"[" << sectionName << L"]\n";

        for (const auto& comment : sectionData.Comments) {
            out << L"; " << comment << L"\n";
        }

        for (const auto& [key, iniVal] : sectionData) {

            // Write comments first (on their own lines)
            for (const auto& comment : iniVal.Comments) {
                out << L"; " << comment << L"\n";
            }

            out << key << L"=";

            if (std::holds_alternative<std::wstring>(iniVal.value)) {
                out << std::get<std::wstring>(iniVal.value);
            }
            else if (std::holds_alternative<bool>(iniVal.value)) {
                out << (std::get<bool>(iniVal.value) ? L"true" : L"false");
            }
            else if (std::holds_alternative<unsigned int>(iniVal.value)) {
                out << std::get<unsigned int>(iniVal.value);
            }
            else if (std::holds_alternative<float>(iniVal.value)) {
                out << std::get<float>(iniVal.value);
            }
            else if (std::holds_alternative<SpecialValue>(iniVal.value)) {
                switch (std::get<SpecialValue>(iniVal.value)) {
                case SpecialValue::Default: out << L"Default"; break;
                case SpecialValue::Auto: out << L"Auto"; break;
                }
            }

            out << L"\n";  // end the line for the current key-value pair
        }

        out << L"\n";  // end the line for the current key-value pair
    }

    return out.str();
}


bool Configurationator::deserialize(const std::wstring& ini_data) {
    std::wstringstream ss(ini_data);
    std::wstring line, currentSection;

    while (std::getline(ss, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';') continue;  // Skip empty lines and comments.

        if (line[0] == '[' && line[line.size() - 1] == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::wstring key = trim(line.substr(0, pos));
            std::wstring valueStr = trim(line.substr(pos + 1));

            ini_value& parsedValue = configData[currentSection][key];

            bool parsed = parseIniValue(parsedValue, valueStr);
        }
    }

    return true;
}
bool Configurationator::parseIniValue(ini_value& receiver, const std::wstring& valueStr) {
    // SpecialValue type handling
    if (std::find_if(receiver.Acceptable_Values.begin(),
        receiver.Acceptable_Values.end(),
        [&valueStr](const auto& val) {
            return std::holds_alternative<std::wstring>(val) &&
                std::get<std::wstring>(val) == valueStr;
        }) != receiver.Acceptable_Values.end()) {
        receiver.value = SpecialValue::Auto;  // This seems off, might want to set the actual SpecialValue.
        receiver.loaded_status = LoadStatus::Present_ReadOkay;
        return true;
    }

    // Boolean type handling
    if (AVTUtils::contains(receiver.Acceptable_Types, AVT::Boolean) &&
        (valueStr == L"true" || valueStr == L"false")) {
        receiver.value = (valueStr == L"true");
        receiver.loaded_status = LoadStatus::Present_ReadOkay;
        return true;
    }

    // Unsigned integer type handling
    if (AVTUtils::contains(receiver.Acceptable_Types, AVT::Unsigned_Integer)) {
        try {
            unsigned int uValue = std::stoul(valueStr);
            if (receiver.Acceptable_Values.empty() ||
                std::find_if(receiver.Acceptable_Values.begin(), receiver.Acceptable_Values.end(),
                    [&uValue](const value_type& val) {
                        return std::holds_alternative<unsigned int>(val) && std::get<unsigned int>(val) == uValue;
                    }) != receiver.Acceptable_Values.end()) {
                receiver.value = uValue;
                receiver.loaded_status = LoadStatus::Present_ReadOkay;
                return true;
            }
        }
        catch (const std::exception&) {
            // Handle exception - conversion failed
        }
    }

    // Float type handling
    if (AVTUtils::contains(receiver.Acceptable_Types, AVT::Float)) {
        try {
            float fValue = std::stof(valueStr);
            if (receiver.Acceptable_Values.empty() ||
                std::find_if(receiver.Acceptable_Values.begin(), receiver.Acceptable_Values.end(),
                    [&fValue](const value_type& val) {
                        return std::holds_alternative<float>(val) && std::get<float>(val) == fValue;
                    }) != receiver.Acceptable_Values.end()) {
                receiver.value = fValue;
                receiver.loaded_status = LoadStatus::Present_ReadOkay;
                return true;
            }
        }
        catch (const std::exception&) {
            // Handle exception - conversion failed
        }
    }

    // String type handling
    if (AVTUtils::contains(receiver.Acceptable_Types, AVT::String)) {
        if (receiver.Acceptable_Values.empty() ||
            std::find_if(receiver.Acceptable_Values.begin(),
                receiver.Acceptable_Values.end(),
                [&valueStr](const auto& val) {
                    return std::holds_alternative<std::wstring>(val) &&
                        std::get<std::wstring>(val) == valueStr;
                }) != receiver.Acceptable_Values.end()) {
            receiver.value = valueStr;
            receiver.loaded_status = LoadStatus::Present_ReadOkay;
            return true;
        }
    }

    receiver.loaded_status = LoadStatus::Present_Malformed;
    return false;
}

Configurationator::ini_value::ini_value(const ini_value& other)
    : value(other.value),
    loaded_status(other.loaded_status),
    DefaultValue(other.DefaultValue),
    Acceptable_Types(other.Acceptable_Types),
    Acceptable_Values(other.Acceptable_Values),
    Comments(other.Comments)
{ }

Configurationator::ini_value::ini_value()
    : value(),
    loaded_status(),
    DefaultValue(),
    Acceptable_Types(AcceptedValueTypes::NotSet),
    Acceptable_Values(),
    Comments() {}


Configurationator::ini_value& Configurationator::ini_value::operator=(const ini_value& other) {
    if (this != &other) { // check for self-assignment
        value = other.value;
        loaded_status = other.loaded_status;

        // Copy comments if the current instance doesn't have any
        if (Comments.empty() && !other.Comments.empty()) {
            Comments = other.Comments;
        }

        // Copy acceptable values if the current instance doesn't have any
        if (Acceptable_Values.empty() && !other.Acceptable_Values.empty()) {
            Acceptable_Values = other.Acceptable_Values;
        }
    }
    return *this;
}


bool Configurationator::ini_value::operator==(const ini_value& rhs) {
    return (this == &rhs) ||
        (
            (value == rhs.value) &&
            (loaded_status == rhs.loaded_status)
            );
}

bool Configurationator::ini_value::operator!=(const ini_value& rhs) {
    return !(*this == rhs);
}

// Comparison operators for SpecialValue
bool operator==(Configurationator::SpecialValue lhs, Configurationator::SpecialValue rhs) {
    return static_cast<int>(lhs) == static_cast<int>(rhs);
}

bool operator!=(Configurationator::SpecialValue lhs, Configurationator::SpecialValue rhs) {
    return !(lhs == rhs);
}

// Comparison operators for LoadStatus
bool operator==(Configurationator::LoadStatus lhs, Configurationator::LoadStatus rhs) {
    return static_cast<int>(lhs) == static_cast<int>(rhs);
}

bool operator!=(Configurationator::LoadStatus lhs, Configurationator::LoadStatus rhs) {
    return !(lhs == rhs);
}

// Comparison operators for AcceptedValueTypes
bool operator==(Configurationator::AcceptedValueTypes lhs, Configurationator::AcceptedValueTypes rhs) {
    return static_cast<int>(lhs) == static_cast<int>(rhs);
}

bool operator!=(Configurationator::AcceptedValueTypes lhs, Configurationator::AcceptedValueTypes rhs) {
    return !(lhs == rhs);
}
