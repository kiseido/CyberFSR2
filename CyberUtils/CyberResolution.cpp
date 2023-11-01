#include "pch.h"
#include "CyberResolution.h"

#include <vector>

#include <algorithm> // For std::max
#include <cstdlib> // For std::div
#include <numeric>
#include <initializer_list>

using ResolutionAxis = CyberTypes::ResolutionAxis_i32;
using Resolution = CyberTypes::Resolution_i32;
using ResolutionList = CyberTypes::ResolutionList_i32;
using ScaleRatio = CyberTypes::ScaleRatio_i32;

namespace CyberUtils {

    CyberTypes::ResolutionList_i32 AlignedResolutionList::MakeList(
        const CyberTypes::Resolution_i32& aspect_ratio,
        const CyberTypes::Resolution_i32& align_to,
        const CyberTypes::Resolution_i32& minValues,
        const CyberTypes::Resolution_i32& maxValues
    ) {

        CyberTypes::ResolutionList_i32 output;

        // Ensure that at least one of maxRes's dimensions is greater than 0.
        if (maxValues.width <= 0 && maxValues.height <= 0) {
            //std::cerr << "Error: At least one of maxRes's dimensions must be greater than 0." << std::endl;
            return output;
        }

        // Calculate the minimum and maximum factors to multiply the aspect ratio by.
        const ResolutionAxis factorWidth = maxValues.width / aspect_ratio.width;
        const ResolutionAxis factorHeight = maxValues.height / aspect_ratio.height;
        const ResolutionAxis maxFactor = std::max(factorWidth, factorHeight);

        ResolutionAxis minFactor = 1;

        // Jog to get over the minimum axis values
        for (; minFactor <= maxFactor; minFactor++) {

            const Resolution resolution = aspect_ratio * minFactor;

            if (resolution.IsUnderBounds(minValues) == false) {
                break;
            }
        }

        // Generate resolutions.
        for (ResolutionAxis factor = minFactor; factor <= maxFactor; factor++) {

            const Resolution resolution = aspect_ratio * factor;

            // Exit once we exceeed the max axis values
            if (resolution.IsOverBounds(maxValues)) {
                break;
            }

            // Add if resolution is aligned.
            if (resolution.isAligned(align_to)) {
                output.push_back(resolution);
            }
        }
        return output;
    }

    AlignedResolutionList::AlignedResolutionList(
        const CyberTypes::Resolution_i32& aspect_ratio,
        const CyberTypes::Resolution_i32& align_to,
        const CyberTypes::Resolution_i32& minmum_axis_values,
        const CyberTypes::Resolution_i32& maximum_axis_values
    ) : init_params(aspect_ratio, align_to, minmum_axis_values, maximum_axis_values), resolutions(MakeList(aspect_ratio, align_to, minmum_axis_values, maximum_axis_values)) {

    }

    AlignedResolutionList::Init_Params::Init_Params(
        const CyberTypes::Resolution_i32& aspect_ratio,
        const CyberTypes::Resolution_i32& align_to,
        const CyberTypes::Resolution_i32& minmum_axis_values,
        const CyberTypes::Resolution_i32& maximum_axis_values
    ) : aspect_ratio(aspect_ratio), align_to(align_to), minimumAxisValues(minmum_axis_values), maximumAxisValues(maximum_axis_values) {

    }

    bool AlignedResolutionList::operator==(const AlignedResolutionList& other) const {
        return init_params.aspect_ratio == other.init_params.aspect_ratio &&
            init_params.align_to == other.init_params.align_to &&
            init_params.minimumAxisValues == other.init_params.minimumAxisValues &&
            init_params.maximumAxisValues == other.init_params.maximumAxisValues;
    }

    CyberUtils::ResolutionDatabase::ListPtr ResolutionDatabase::getResolutions(const Resolution& aspect_ratio, const Resolution& align_to, const Resolution& minimumAxisValues, const Resolution& maximumAxisValues) {

        const auto begin = lists.begin();
        const auto end = lists.end();


        constexpr size_t ResCount = 2 * 4;
        constexpr size_t ResSize = sizeof(int32_t);
        constexpr size_t ResArraySize = ResSize * ResCount;
        constexpr size_t NativeSize = sizeof(char);
        constexpr size_t NativeCount = (ResArraySize / NativeSize) + ((ResArraySize % NativeSize == 0) ? 0 : 1);

        std::array<char, NativeCount> key;;

        // pack the resolutions int32 bits into the char array

        auto packResolution = [&key](const Resolution& res, size_t offset) {
            uint32_t width = static_cast<uint32_t>(res.width);
            uint32_t height = static_cast<uint32_t>(res.height);

            key[offset] = width & 0xFF;
            key[offset + 1] = (width >> 8) & 0xFF;
            key[offset + 2] = (width >> 16) & 0xFF;
            key[offset + 3] = (width >> 24) & 0xFF;

            key[offset + 4] = height & 0xFF;
            key[offset + 5] = (height >> 8) & 0xFF;
            key[offset + 6] = (height >> 16) & 0xFF;
            key[offset + 7] = (height >> 24) & 0xFF;
            };

        packResolution(aspect_ratio, 0);
        packResolution(align_to, ResSize * 2);
        packResolution(minimumAxisValues, ResSize * 4);
        packResolution(maximumAxisValues, ResSize * 6);

        const std::string_view keyString(key.data(),key.size());

        auto ptr = lists[keyString];

        if (ptr == nullptr) {
            const AlignedResolutionList result(aspect_ratio, align_to, minimumAxisValues, maximumAxisValues);
            ptr = std::make_shared<AlignedResolutionList>(result);
            lists[keyString] = ptr;
        }

        return ptr;
    }

}