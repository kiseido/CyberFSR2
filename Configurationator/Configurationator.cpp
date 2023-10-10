#include "pch.h"
#include "framework.h"

#include "Configurationator.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

using ACT = Configurationator::AcceptedValueTypes;

namespace ACTUtils {


    ACT pack(ACT a, ACT b) {
        return static_cast<ACT>(
            static_cast<int>(a) | static_cast<int>(b)
            );
    }

    ACT pack(ACT a, ACT b, ACT c) {
        return static_cast<ACT>(
            static_cast<int>(a) | static_cast<int>(b) | static_cast<int>(c)
            );
    }

    bool contains(ACT value, ACT flag) {
        return (static_cast<int>(value) & static_cast<int>(flag)) != 0;
    }

}
inline ACT operator| (ACT a, ACT b) {
    return static_cast<ACT>(static_cast<int>(a) | static_cast<int>(b));
}

inline ACT& operator|= (ACT& a, ACT b) {
    return a = a | b;
}

inline ACT operator& (ACT a, ACT b) {
    return static_cast<ACT>(static_cast<int>(a) & static_cast<int>(b));
}

inline ACT& operator&= (ACT& a, ACT b) {
    return a = a & b;
}

// Helper function to trim whitespace from a string.
static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t");
    size_t end = str.find_last_not_of(" \t");
    return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
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
    const std::vector<std::string>& Comments
)
    : value(DefaultValue),
    DefaultValue(DefaultValue),
    loaded_status(LoadStatus::Missing),
    Acceptable_Types(AcceptableTypes),
    Acceptable_Values(AcceptableValues),
    Comments(Comments)
{ }

// Constructor implementation
Configurationator::Configurationator() {
    loadDefaultValues();
}


void Configurationator::saveToFile(const std::string& filename) {
    std::ofstream file(filename);

    if (!file.is_open()) {
        // Handle file opening error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Unable to open file for writing: " + filename);
    }

    std::string serializedData = serialize();
    file << serializedData;

    if (file.fail()) {
        // Handle file writing error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Error writing to file: " + filename);
    }

    file.close();
}


Configurationator::ini_section& Configurationator::operator[](const std::string& key) {
    return configData[key];
}

void Configurationator::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        // Handle file opening error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Unable to open file for reading: " + filename);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    if (!deserialize(buffer.str())) {
        // Handle INI deserialization error (e.g., throw exception, log error, etc.)
        throw std::runtime_error("Error deserializing INI data from file: " + filename);
    }

    file.close();
}

std::string Configurationator::serialize() {
    std::stringstream out;

    for (const auto& [sectionName, sectionData] : configData) {
        out << "[" << sectionName << "]\n";
        for (const auto& [key, iniVal] : sectionData) {
            out << key << "=";

            if (std::holds_alternative<std::string>(iniVal.value)) {
                out << std::get<std::string>(iniVal.value);
            }
            else if (std::holds_alternative<bool>(iniVal.value)) {
                out << (std::get<bool>(iniVal.value) ? "true" : "false");
            }
            else if (std::holds_alternative<unsigned int>(iniVal.value)) {
                out << std::get<unsigned int>(iniVal.value);
            }
            else if (std::holds_alternative<float>(iniVal.value)) {
                out << std::get<float>(iniVal.value);
            }
            else if (std::holds_alternative<SpecialValue>(iniVal.value)) {
                switch (std::get<SpecialValue>(iniVal.value)) {
                case SpecialValue::Default: out << "Default"; break;
                case SpecialValue::Auto: out << "Auto"; break;
                }
            }

            if (!iniVal.Comments.empty()) {
                for (const auto& comment : iniVal.Comments) {
                    out << "; " << comment << "\n";
                }
            }
            else {
                out << "\n";
            }
        }
    }

    return out.str();
}

bool Configurationator::deserialize(const std::string& ini_data) {
    std::stringstream ss(ini_data);
    std::string line, currentSection;

    while (std::getline(ss, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';') continue;  // Skip empty lines and comments.

        if (line[0] == '[' && line[line.size() - 1] == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = trim(line.substr(0, pos));
            std::string valueStr = trim(line.substr(pos + 1));

            ini_value& parsedValue = configData[currentSection][key];

            bool parsed = parseIniValue(parsedValue, valueStr);
        }
    }

    return true;
}

bool Configurationator::parseIniValue(ini_value& receiver, const std::string& valueStr) {
    // SpecialValue type handling
    if (auto it = std::find_if(receiver.Acceptable_Values.begin(),
        receiver.Acceptable_Values.end(),
        [&valueStr](const auto& val) {
            return std::holds_alternative<std::string>(val) &&
                std::get<std::string>(val) == valueStr;
        });
        it != receiver.Acceptable_Values.end()) {
        receiver.value = SpecialValue::Auto;
        receiver.loaded_status = LoadStatus::Present_ReadOkay;
        return true;
    }

    // Boolean type handling
    if (ACTUtils::contains(receiver.Acceptable_Types, ACT::Boolean) &&
        (valueStr == "true" || valueStr == "false")) {
        receiver.value = (valueStr == "true");
        receiver.loaded_status = LoadStatus::Present_ReadOkay;
        return true;
    }

    // Unsigned integer type handling
    if (ACTUtils::contains(receiver.Acceptable_Types, ACT::Unsigned_Integer)) {
        try {
            unsigned int value = std::stoul(valueStr);
            if (receiver.Acceptable_Values.empty() ||
                std::find(receiver.Acceptable_Values.begin(), receiver.Acceptable_Values.end(), value) != receiver.Acceptable_Values.end()) {
                receiver.value = value;
                receiver.loaded_status = LoadStatus::Present_ReadOkay;
                return true;
            }
        }
        catch (const std::exception&) {
            // Handle exception - conversion failed
        }
    }

    // Float type handling
    if (ACTUtils::contains(receiver.Acceptable_Types, ACT::Float)) {
        try {
            float value = std::stof(valueStr);
            if (receiver.Acceptable_Values.empty() ||
                std::find(receiver.Acceptable_Values.begin(), receiver.Acceptable_Values.end(), value) != receiver.Acceptable_Values.end()) {
                receiver.value = value;
                receiver.loaded_status = LoadStatus::Present_ReadOkay;
                return true;
            }
        }
        catch (const std::exception&) {
            // Handle exception - conversion failed
        }
    }

    // String type handling
    if (ACTUtils::contains(receiver.Acceptable_Types, ACT::String)) {
        if (receiver.Acceptable_Values.empty() ||
            std::find_if(receiver.Acceptable_Values.begin(),
                receiver.Acceptable_Values.end(),
                [&valueStr](const auto& val) {
                    return std::holds_alternative<std::string>(val) &&
                        std::get<std::string>(val) == valueStr;
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

Configurationator::ini_value& Configurationator::ini_value::operator=(const ini_value& other) {
    if (this != &other) { // check for self-assignment
        value = other.value;
        loaded_status = other.loaded_status;

        // Manually handle the assignment for const members using const_cast and placement new.
        const_cast<AcceptedValueTypes&>(Acceptable_Types) = other.Acceptable_Types;
        new (&const_cast<value_type&>(DefaultValue)) value_type(other.DefaultValue);
        new (&const_cast<std::vector<value_type>&>(Acceptable_Values)) std::vector<value_type>(other.Acceptable_Values);
        new (&const_cast<std::vector<std::string>&>(Comments)) std::vector<std::string>(other.Comments);
    }
    return *this;
}

