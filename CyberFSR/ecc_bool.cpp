#include "pch.h"
#include "ecc_bool.h"

template <typename T>
ECC_BOOL<T>::ECC_BOOL(const bool val)
{
    set(val);
}

template <typename T>
void ECC_BOOL<T>::set(const bool val)
{
    std::memset(value, val ? 0xFF : 0x00, ValueSize);
}

template <typename T>
ECC_BOOL_STATE ECC_BOOL<T>::get() const
{
    ECC_BOOL_STATE state;
    calculateValueAndConfidence(state.value, state.value_confidence);
    state.error = (state.value_confidence != 1.0f);
    return state;
}

template <typename T>
void ECC_BOOL<T>::calculateValueAndConfidence(bool& outValue, float& outConfidence) const
{
    int trueCount = 0;
    int falseCount = 0;

    for (std::size_t arrIndex = ValueSize; arrIndex > 0; --arrIndex)
    {
        std::uint8_t byteValue = value[arrIndex - 1];
        if (byteValue == 0xFF)
        {
            trueCount += 8;
        }
        else if (byteValue == 0x00)
        {
            falseCount += 8;
        }
        else
        {
            for (int bitIndex = 8; bitIndex >= 0; --bitIndex)
            {
                bool bitValue = ((byteValue >> bitIndex) & true);
                if (bitValue)
                {
                    trueCount += 1;
                }
                else
                {
                    falseCount += 1;
                }
            }
        }
    }

    outValue = (trueCount > falseCount);

    const int largest = (trueCount > falseCount) ? trueCount : falseCount;

    outConfidence = static_cast<float>(largest) / (ValueSize * 8);
}

// Explicit template instantiation
template class ECC_BOOL<unsigned __int64>;