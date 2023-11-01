#pragma once

#include "CyberTypes.h"
#include <unordered_map>

namespace CyberUtils {

    struct AlignedResolutionList {
        struct InitParams {
            const CyberTypes::Resolution_i32 aspect_ratio;
            const CyberTypes::Resolution_i32 align_to;
            const CyberTypes::Resolution_i32 minimumAxisValues;
            const CyberTypes::Resolution_i32 maximumAxisValues;

            InitParams(
                const CyberTypes::Resolution_i32& aspect_ratio,
                const CyberTypes::Resolution_i32& align_to,
                const CyberTypes::Resolution_i32& minValues,
                const CyberTypes::Resolution_i32& maxValues
            );

            bool operator==(const InitParams& other) const;

        };
        static CyberTypes::ResolutionList_i32 make_list(const InitParams& in);


        const InitParams init_params;
        const CyberTypes::ResolutionList_i32 resolutions;

        std::optional<CyberTypes::Resolution_i32> get_closest_resolution(const CyberTypes::Resolution_i32& target_resolution) const;

        AlignedResolutionList(const InitParams& in);

        bool operator==(const AlignedResolutionList& other) const;
    };

    struct ResolutionDatabase {
        using ListPtr = std::shared_ptr<const AlignedResolutionList>;
        static constexpr size_t DEFAULT_MAX_SIZE = 100;
        size_t MAX_SIZE = DEFAULT_MAX_SIZE;

        ListPtr generate_resolutions(const CyberTypes::Resolution_i32& aspect_ratio, const CyberTypes::Resolution_i32& align_to, const CyberTypes::Resolution_i32& minimumAxisValues, const CyberTypes::Resolution_i32& maximumAxisValues);
        
        ListPtr find_first_list_with_params(const AlignedResolutionList::InitParams& params);
        ListPtr find_first_list_with_aspect_ratio(const CyberTypes::Resolution_i32& aspect_ratio);
        ListPtr find_first_list_with_align_to(const CyberTypes::Resolution_i32& align_to);
        
        std::optional<CyberTypes::Resolution_i32> find_first_resolution_near(const CyberTypes::Resolution_i32& target_resolution);
        std::optional<CyberTypes::Resolution_i32> find_first_scaled_resolution(const CyberTypes::Resolution_i32& aspect_ratio, const CyberTypes::ScaleRatio_i32& scalar);

        void prune();
    private:
        void move_to_front(std::list<ListPtr>::iterator& it);

        std::list<ListPtr> lru_lists;

    };
}
