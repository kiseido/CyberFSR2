#pragma once

#include "CyberTypes.h"
#include <unordered_map>

namespace CyberUtils {

    struct AlignedResolutionList {
        struct Init_Params {
            const CyberTypes::Resolution_i32 aspect_ratio;
            const CyberTypes::Resolution_i32 align_to;
            const CyberTypes::Resolution_i32 minimumAxisValues;
            const CyberTypes::Resolution_i32 maximumAxisValues;

            Init_Params(
                const CyberTypes::Resolution_i32& aspect_ratio,
                const CyberTypes::Resolution_i32& align_to,
                const CyberTypes::Resolution_i32& minValues,
                const CyberTypes::Resolution_i32& maxValues
            );
        };

        const Init_Params init_params;

        const CyberTypes::ResolutionList_i32 resolutions;

        static CyberTypes::ResolutionList_i32 MakeList(
            const CyberTypes::Resolution_i32& aspect_ratio,
            const CyberTypes::Resolution_i32& align_to,
            const CyberTypes::Resolution_i32& minValues,
            const CyberTypes::Resolution_i32& maxValues
        );

        // Constructor for initialization
        AlignedResolutionList(
            const CyberTypes::Resolution_i32& aspect_ratio,
            const CyberTypes::Resolution_i32& align_to,
            const CyberTypes::Resolution_i32& minValues,
            const CyberTypes::Resolution_i32& maxValues
        );

        bool operator==(const AlignedResolutionList& other) const;
    };

    struct ResolutionDatabase {
        typedef std::shared_ptr<const AlignedResolutionList> ListPtr;

        ListPtr getResolutions(const CyberTypes::Resolution_i32& aspect_ratio, const CyberTypes::Resolution_i32& align_to, const CyberTypes::Resolution_i32& minimumAxisValues, const CyberTypes::Resolution_i32& maximumAxisValues);

    private:
        std::unordered_map<std::string_view,ListPtr> lists;
    };
}
