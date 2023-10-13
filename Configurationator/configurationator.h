#include "pch.h"


#ifndef Configurationator_h
#define Configurationator_h

#include <string>
#include <map>
#include <variant>
#include <vector>



struct Configurationator {
    enum class FileLoadStatus {
        Success,
        FileNotFound,
        DeserializeError
    };

    enum class SpecialValue {
        NotSet = 0,
        Default,
        Auto,
    };

    enum class LoadStatus {
        NotSet = 0,
        Missing = 1,
        Present_Malformed=1<<1,
        Present_ReadOkay=1<<2,
    };

    enum class AcceptedValueTypes {
        NotSet = 0,
        String = 0b1,
        Unsigned_Integer = 0b1 << 1,
        Float = 0b1 << 2,
        Boolean = 0b1 << 3,
        SpecialValue = 0b1 << 4,
    };

    using value_type = std::variant<std::string, bool, unsigned int, float, SpecialValue>;

    struct ini_value {
    public:
        value_type value;
        LoadStatus loaded_status;
        value_type DefaultValue;
        AcceptedValueTypes Acceptable_Types;
        std::vector<value_type> Acceptable_Values;
        std::vector<std::string> Comments;
        ini_value();
        ini_value(
            value_type value,
            LoadStatus loadStatus
        );
        ini_value(
            value_type DefaultValue,
            AcceptedValueTypes AcceptableTypes,
            const std::vector<value_type>& AcceptableValues,
            const std::vector<std::string>& Comments
        );
        ini_value(const ini_value&);
        ini_value& operator=(const ini_value& other);
        bool operator==(const ini_value& rhs);
        bool operator!=(const ini_value& rhs);
    };

    struct ini_section : public std::map<std::string, ini_value> {
        std::vector<std::string> Comments;
        ini_section();
        ini_section(const std::vector<std::string>&);
        ini_section(const ini_section&);
    };

    using ini_data = std::map<std::string, ini_section>;

    FileLoadStatus loadFromFile(const std::string& filename);
    void saveToFile(const std::string& filename);

    std::string serialize();
    bool deserialize(const std::string& ini_data);

    ini_section& operator[](const std::string& key);

protected:
    Configurationator();

    static bool parseIniValue(ini_value& receiver, const std::string& valueStr);

    ini_data configData;
};

// Comparison operators for SpecialValue
bool operator==(Configurationator::SpecialValue lhs, Configurationator::SpecialValue rhs);

bool operator!=(Configurationator::SpecialValue lhs, Configurationator::SpecialValue rhs);

// Comparison operators for LoadStatus
bool operator==(Configurationator::LoadStatus lhs, Configurationator::LoadStatus rhs);

bool operator!=(Configurationator::LoadStatus lhs, Configurationator::LoadStatus rhs);

// Comparison operators for AcceptedValueTypes
bool operator==(Configurationator::AcceptedValueTypes lhs, Configurationator::AcceptedValueTypes rhs);

bool operator!=(Configurationator::AcceptedValueTypes lhs, Configurationator::AcceptedValueTypes rhs);

namespace AVTUtils {
    inline Configurationator::AcceptedValueTypes pack() {
        return Configurationator::AcceptedValueTypes::NotSet;
    }

    template<typename... Args>
    inline Configurationator::AcceptedValueTypes pack(Configurationator::AcceptedValueTypes first, Args... args) {
        return static_cast<Configurationator::AcceptedValueTypes>(
            static_cast<int>(first) | static_cast<int>(pack(args...))
            );
    }
}


#endif