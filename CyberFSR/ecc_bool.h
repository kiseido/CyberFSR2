#ifndef ECC_BOOL_H
#define ECC_BOOL_H

#include <cmath>
#include <type_traits>
#include <cstring>

struct ECC_BOOL_STATE
{
    bool value;
    bool error;
    float value_confidence;
};

template <typename T>
class ECC_BOOL
{
    static_assert(sizeof(T) >= 1, "ECC_BOOL requires a size of at least one byte.");
    static_assert(std::is_integral_v<T>, "ECC_BOOL requires an integral type.");

public:
    static constexpr std::size_t ValueSize = sizeof(T);

    ECC_BOOL() = default;
    ECC_BOOL(const ECC_BOOL& other) = default;
    ECC_BOOL& operator=(const ECC_BOOL& other) = default;
    ECC_BOOL(const bool val);

    void set(const bool val);
    ECC_BOOL_STATE get() const;

private:
    std::uint8_t value[ValueSize];
    static_assert(sizeof(value) <= sizeof(T), "ECC_BOOL exceeds parent type size");

    void calculateValueAndConfidence(bool& outValue, float& outConfidence) const;
};

#endif  // ECC_BOOL_H
