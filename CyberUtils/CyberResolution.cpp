#include "pch.h"
#include "CyberResolution.h"

#include <vector>

#include <algorithm>
#include <cstdlib>
#include <numeric>
#include <initializer_list>

using ResolutionAxis = CyberTypes::ResolutionAxis_i32;
using Resolution = CyberTypes::Resolution_i32;
using ResolutionList = CyberTypes::ResolutionList_i32;
using ScaleRatio = CyberTypes::ScaleRatio_i32;

namespace CyberUtils {

    CyberTypes::ResolutionList_i32 AlignedResolutionList::make_list( const InitParams& params) {

        const auto& maxValues = params.maximumAxisValues;
        const auto& minValues = params.minimumAxisValues;
        const auto& aspect_ratio = params.aspect_ratio;
        const auto& align_to = params.align_to;

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

    AlignedResolutionList::AlignedResolutionList(const InitParams& params)
        : init_params(params), resolutions(make_list(params)) {
        // Constructor body (if needed)
    }

    std::optional<CyberTypes::Resolution_i32> AlignedResolutionList::get_closest_resolution(const CyberTypes::Resolution_i32& target_resolution) const {

        std::optional<CyberTypes::Resolution_i32> output = std::nullopt;

        if (resolutions.empty()) {
            return output;
        }

        using CalcT = int64_t;

        const CalcT targetPixCount = target_resolution.GetPixelCount<CalcT>();

        const auto it = std::lower_bound(resolutions.begin(), resolutions.end(), targetPixCount,
            [](const CyberTypes::Resolution_i32& res, CalcT val) {
                return res.GetPixelCount<CalcT>() < val;
            });

        // Three cases to consider:
        // 1. Found exact match, or it is the smallest resolution that is greater than the target.
        // 2. It is the end iterator, meaning all resolutions in the list are smaller than the target.
        // 3. It is somewhere in the middle of the list.

        if (it == resolutions.begin()) {
            output = *it;
        }
        else if (it == resolutions.end()) {
            output = *std::prev(it);
        }
        else {
            const auto prev_it = std::prev(it);
            const CalcT diff_curr = std::abs(it->GetPixelCount<CalcT>() - targetPixCount);
            const CalcT diff_prev = std::abs(prev_it->GetPixelCount<CalcT>() - targetPixCount);


            if (diff_curr > diff_prev)
                output = *prev_it;
            else
                output = *it;
        }
        return output;
    }


    AlignedResolutionList::InitParams::InitParams(
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

    ResolutionDatabase::ListPtr ResolutionDatabase::find_first_list_with_params(const AlignedResolutionList::InitParams& params) {
        for (auto it = lru_lists.begin(); it != lru_lists.end(); it++) {
            const auto listPtr = *it;
            if (listPtr->init_params == params) {
                move_to_front(it);
                return listPtr;
            }
        }
        return nullptr;
    }

    ResolutionDatabase::ListPtr ResolutionDatabase::find_first_list_with_aspect_ratio(const CyberTypes::Resolution_i32& aspect_ratio) {
        for (auto it = lru_lists.begin(); it != lru_lists.end(); it++) {
            const auto& listPtr = *it;
            if (listPtr->init_params.aspect_ratio == aspect_ratio) {
                move_to_front(it);
                return *it;
            }
        }
        return nullptr;  // Return null if not found
    }

    ResolutionDatabase::ListPtr ResolutionDatabase::find_first_list_with_align_to(const CyberTypes::Resolution_i32& align_to) {
        for (auto it = lru_lists.begin(); it != lru_lists.end(); it++) {
            const auto& listPtr = *it;
            if (listPtr->init_params.align_to == align_to) {
                move_to_front(it);
                return *it;
            }
        }
        return nullptr;  // Return null if not found
    }

    CyberUtils::ResolutionDatabase::ListPtr ResolutionDatabase::generate_resolutions(const Resolution& aspect_ratio, const Resolution& align_to, const Resolution& minimumAxisValues, const Resolution& maximumAxisValues) {

        const AlignedResolutionList::InitParams param(aspect_ratio, align_to, minimumAxisValues, maximumAxisValues);

        const auto foundPtr = find_first_list_with_params(param);

        if (foundPtr != nullptr)
            return foundPtr;

        const auto newPtr = std::make_shared<AlignedResolutionList>(param);

        lru_lists.emplace_front(newPtr);

        prune();

        return newPtr;
    }

    void ResolutionDatabase::prune() {
        while (lru_lists.size() > MAX_SIZE) {
            auto last = lru_lists.end();
            last--;
            lru_lists.pop_back();
        }
    }
    void ResolutionDatabase::move_to_front(std::list<ListPtr>::iterator& it) {
        if (it != lru_lists.begin()) { // Check if it is not already at the front
            lru_lists.splice(lru_lists.begin(), lru_lists, it);
        }
    }

    std::optional<CyberTypes::Resolution_i32> ResolutionDatabase::find_first_resolution_near(const CyberTypes::Resolution_i32& target_resolution) {

        const CyberTypes::Resolution_i32 target_aspect_ratio = target_resolution.GetSimplified();

        const auto foundListPtr = find_first_list_with_aspect_ratio(target_aspect_ratio);

        if (foundListPtr == nullptr)
            return std::nullopt;

        auto nearest_resolution = foundListPtr->get_closest_resolution(target_resolution);

        return nearest_resolution;
    }
}