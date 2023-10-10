#include "pch.h"


#ifndef Configurationator_h
#define Configurationator_h

#include <string>
#include <map>
#include <variant>
#include <vector>



struct Configurationator {
    enum class SpecialValue {
        Default,
        Auto
    };

    enum class LoadStatus {
        Missing = 0,
        Present_Malformed,
        Present_ReadOkay,
    };

    enum class AcceptedValueTypes {
        NotSet = 0,
        String = 0b1,
        Unsigned_Integer = 0b1 << 1,
        Float = 0b1 << 2,
        Boolean = 0b1 << 3
    };

    using value_type = std::variant<std::string, bool, unsigned int, float, SpecialValue>;

    struct ini_value {
        value_type value;
        LoadStatus loaded_status;
        const value_type DefaultValue;
        const AcceptedValueTypes Acceptable_Types;
        const std::vector<value_type> Acceptable_Values;
        const std::vector<std::string> Comments;
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

    };

    using ini_section = std::map<std::string, ini_value>;
    using ini_data = std::map<std::string, ini_section>;

    void loadFromFile(const std::string& filename);
    void saveToFile(const std::string& filename);

    virtual void loadDefaultValues() = 0;

    std::string serialize();
    bool deserialize(const std::string& ini_data);

    ini_section& operator[](const std::string& key);

protected:
    Configurationator();

    static bool parseIniValue(ini_value& receiver, const std::string& valueStr);

    ini_data configData;
};

#endif