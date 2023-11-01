#pragma once

#include <numeric>

#include <string_view>

#include <vector>

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_defs.h>

namespace CyberTypes::Utils {

    // Define the wrapper class template
    template<typename BaseT>
    struct Wrapper {
    private:
        BaseT _val;

    public:
        Wrapper() : _val() {}
        Wrapper(const BaseT& val) : _val(val) {}

        Wrapper& operator=(const BaseT& val) {
            _val = val;
            return *this;
        }
        Wrapper& operator=(const Wrapper<BaseT>& other) {
            _val = other._val;
            return *this;
        }

        const BaseT& get() const {
            return _val;
        }

        BaseT& get() {
            return _val;
        }

        void set(const BaseT& val) {
            _val = val;
        }

        BaseT& getBaseReference() {
            return _val;
        }

        operator const BaseT& () const {
            return _val;
        }
        //std::wostream& operator<<(std::wostream& os);
    };

    template <typename BaseT>
    union UnionWrapper {
        BaseT  inner;
        Wrapper<BaseT> wrapped;
    };

    constexpr std::wstring_view GET_PART_AFTER_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
        return name.substr(prefix.size());
    }

    constexpr bool CHECK_STARTS_WITH(const std::wstring_view& prefix, const std::wstring_view& name) {
        return name.compare(0, prefix.size(), prefix) == 0;
    }

    constexpr std::wstring_view TRY_REMOVE_PREFIX(const std::wstring_view& prefix, const std::wstring_view& name) {
        if (CHECK_STARTS_WITH(prefix, name)) {
            return GET_PART_AFTER_PREFIX(prefix, name);
        }
        else {
            return name;
        }
    }
}

namespace CyberTypes {

    using ResolutionAxis_i32 = std::int32_t;

    template <typename T>
    struct ScaleRatio {
        T numerator;
        T divisor;
    };

    using ScaleRatio_i32 = ScaleRatio<ResolutionAxis_i32>;

    template <typename T>
    struct Resolution {
        T width;
        T height;

       struct DivisionResult { Resolution<T> result; Resolution<T> remainder; };

        bool IsUnderBounds(const Resolution<T>& lowerBoundary) const {
            return
                (
                    (lowerBoundary.width > 0 && width < lowerBoundary.width)
                    ||
                    (lowerBoundary.height > 0 && height < lowerBoundary.height)
                    );
        }

        bool IsOverBounds(const Resolution<T>& upperBoundary) const {
            return
                (
                    (upperBoundary.width > 0 && width > upperBoundary.width)
                    ||
                    (upperBoundary.height > 0 && height > upperBoundary.height)
                    );
        }

        bool isAligned(const Resolution<T>& alignToRes) const {
            bool widthAligned = ((alignToRes.width <= 1) || (width % alignToRes.width == 0));
            bool heightAligned = ((alignToRes.height <= 1) || (height % alignToRes.height == 0));
            return widthAligned && heightAligned;
        }

        template <typename CalcType>
        CalcType GetPixelCount() const {
            CalcType count = width;
            count *= height;
            return count;
        }

        T GetLowestAxis() const {
            return std::min(width, height);
        }

        T GetHighestAxis() const {
            return std::max(width, height);
        }

        Resolution<T> LeastCommonMultiple(const Resolution<T>& other) const {
            return { std::lcm(width, other,width), std::lcm(height, other.height) };
        }

        DivisionResult divWithRemainder(const Resolution<T>& other) const {
            const div_t w = std::div(width, other.width);
            const div_t h = std::div(height, other.height);
            return { Resolution(w.quot, h.quot), Resolution(w.rem, h.rem) };
        }

        Resolution<T> GetSimplified() const {
            T gcd = std::gcd(width, height);
            return { width / gcd, height / gcd };
        }

        Resolution<T> operator*(const ScaleRatio<T>& scalar) const {
            return { (width * scalar.numerator) / scalar.divisor, (height * scalar.numerator) / scalar.divisor };
        }

        Resolution<T> operator*(const T scalar) const {
            return { width * scalar, height * scalar };
        }

        Resolution<T> operator*(const Resolution<T>& other) const {
            return { width * other.width, height * other.height };
        }

        Resolution<T> operator/(const T scalar) const {
            return { width / scalar, height / scalar };
        }

        Resolution<T> operator/(const Resolution<T>& other) const {
            return { width / other.width, height / other.height };
        }

        Resolution<T> operator%(const Resolution<T>& other) const {
            return { width % other.width, height % other.height };
        }

        bool operator<=(const Resolution<T>& other) const {
            return width <= other.width && height <= other.height;
        }
        bool operator>=(const Resolution<T>& other) const {
            return width >= other.width && height >= other.height;
        }

        bool operator==(const Resolution<T>& other) const {
            return width == other.width && height == other.height;
        }
    };

    using Resolution_i32 = Resolution<ResolutionAxis_i32>;

    using ResolutionList_i32 = std::vector<Resolution_i32>;

// #define WrapIt(BaseType) typedef Wrapper<BaseType> CT_##BaseType##_t; typedef union {BaseType base; CT_##BaseType##_t wrapped;} CT_##BaseType##_u; std::wostream& CyberTypes::CT_##BaseType##_u::operator<<(std::wostream& wos)

#define WrapThisTypeAndOperator(BaseType) \
    typedef CyberTypes::Utils::Wrapper<BaseType> CT_##BaseType##_w;\
    typedef CyberTypes::Utils::UnionWrapper<BaseType> CT_##BaseType##_u;\
    std::wostream& operator<<(std::wostream& wos, const CT_##BaseType##_u&)

    struct NVSDK_NGX_FeatureCommonInfo_Internal  {};

    // Define wrapper classes for specific types
    WrapThisTypeAndOperator(AppId);

    WrapThisTypeAndOperator(NVSDK_NGX_GPU_Arch);
    WrapThisTypeAndOperator(NVSDK_NGX_DLSS_Hint_Render_Preset);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureCommonInfo_Internal);
    WrapThisTypeAndOperator(NVSDK_NGX_Version);
    WrapThisTypeAndOperator(NVSDK_NGX_Result);
    WrapThisTypeAndOperator(NVSDK_NGX_Feature);
    WrapThisTypeAndOperator(NVSDK_NGX_Buffer_Format);
    WrapThisTypeAndOperator(NVSDK_NGX_PerfQuality_Value);
    WrapThisTypeAndOperator(NVSDK_NGX_RTX_Value);
    WrapThisTypeAndOperator(NVSDK_NGX_DLSS_Mode);
    WrapThisTypeAndOperator(NVSDK_NGX_DeepDVC_Mode);
    WrapThisTypeAndOperator(NVSDK_NGX_Handle);
    WrapThisTypeAndOperator(NVSDK_NGX_ToneMapperType);
    WrapThisTypeAndOperator(NVSDK_NGX_GBufferType);
    WrapThisTypeAndOperator(NVSDK_NGX_Coordinates);
    WrapThisTypeAndOperator(NVSDK_NGX_Dimensions);
    WrapThisTypeAndOperator(NVSDK_NGX_PathListInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_Logging_Level);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureCommonInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_Resource_VK_Type);
    WrapThisTypeAndOperator(NVSDK_NGX_Opt_Level);
    WrapThisTypeAndOperator(NVSDK_NGX_EngineType);
    WrapThisTypeAndOperator(NVSDK_NGX_Feature_Support_Result);
    WrapThisTypeAndOperator(NVSDK_NGX_Application_Identifier_Type);
    WrapThisTypeAndOperator(NVSDK_NGX_ProjectIdDescription);
    WrapThisTypeAndOperator(NVSDK_NGX_Application_Identifier);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureDiscoveryInfo);
    WrapThisTypeAndOperator(NVSDK_NGX_FeatureRequirement);

#undef WrapThisTypeAndOperator

    class CyString : public std::wstring {
    public:
        CyString();
        CyString(const std::wstring& wstr);
        CyString(const std::wstring_view& wview);
        CyString(const std::string& str);
        CyString(const std::string_view& view);
        CyString(const CyString& other);
        CyString(const char* cstr);
        CyString(const wchar_t* wcstr);
    };

    class CyString_view : public std::wstring_view {
    public:
        CyString_view();
        CyString_view(const std::wstring& wstr);
        CyString_view(const std::wstring_view& wview);
        CyString_view(const wchar_t* wcstr);
        CyString_view(const CyString_view& other);
    };

    struct HighPerformanceCounterInfo {
        long long frequency;
        long long counter;

        HighPerformanceCounterInfo();
        HighPerformanceCounterInfo(const bool& performInitLogic);
        HighPerformanceCounterInfo(const HighPerformanceCounterInfo& other);
    };

    struct CoreInfo {
        int logicalProcessorId;
        long long processorTick;

        CoreInfo();
        CoreInfo(const bool& performInitLogic);
        CoreInfo(const CoreInfo& other);
    };

    struct RTC {
        std::chrono::system_clock::time_point timestamp;

        RTC();
        RTC(const bool& performInitLogic);
        RTC(const RTC& other);
    };

    struct SystemInfo {
        CoreInfo coreInfo;
        HighPerformanceCounterInfo highPerformanceCounterInfo;
        RTC rtc;

        bool DoPerformanceInfo = true;
        bool DoCoreInfo = true;
        bool DoRTC = true;

        SystemInfo();
        SystemInfo(const bool& doCoreInfo, const bool& doPerformanceInfo, const bool& doRTC);
        SystemInfo(const SystemInfo& other);
    };

    std::wstring stringToWstring(const std::string& str);

    struct DLSS_Feature_Flags_Wrapper {
        NVSDK_NGX_DLSS_Feature_Flags inner;

        bool IsHDR();
        bool IsMVLowRes();
        bool IsMVJittered();
        bool IsDepthInverted();
        bool IsDoSharpening();
        bool IsAutoExposure();
        bool IsReserved0();

        DLSS_Feature_Flags_Wrapper& operator=(const NVSDK_NGX_DLSS_Feature_Flags& other);
        operator NVSDK_NGX_DLSS_Feature_Flags() const;
    };

    template <typename ResourceType>
    struct DLSS_Resources_Holder {
        enum Field : UINT {
            Color_enum = 1,
            Output_enum,
            Depth_enum,
            MotionVectors_enum,
            TransparencyMask_enum,
            ExposureTexture_enum,
            BiasCurrentColorMask_enum,
            GBufferAlbedo_enum,
            GBufferRoughness_enum,
            GBufferMetallic_enum,
            GBufferSpecular_enum,
            GBufferSubsurface_enum,
            GBufferNormals_enum,
            GBufferShadingModelId_enum,
            GBufferMaterialId_enum,
            GBufferAttrib0_enum,
            GBufferAttrib1_enum,
            GBufferAttrib2_enum,
            GBufferAttrib3_enum,
            GBufferAttrib4_enum,
            GBufferAttrib5_enum,
            GBufferAttrib6_enum,
            GBufferAttrib7_enum,
            GBufferAttrib8_enum,
            GBufferAttrib9_enum,
            GBufferAttrib10_enum,
            GBufferAttrib11_enum,
            GBufferAttrib12_enum,
            GBufferAttrib13_enum,
            GBufferAttrib14_enum,
            GBufferAttrib15_enum,
            MotionVectors3D_enum,
            IsParticleMask_enum,
            AnimatedTextureMask_enum,
            DepthHighRes_enum,
            MotionVectorsReflection_enum,
            length_enum
        };

        std::array<ResourceType, length_enum> resources;

        ResourceType& Color() { return resources[Field::Color_enum]; }
        ResourceType& Output() { return resources[Field::Output_enum]; }
        ResourceType& Depth() { return resources[Field::Depth_enum]; }
        ResourceType& MotionVectors() { return resources[Field::MotionVectors_enum]; }
        ResourceType& TransparencyMask() { return resources[Field::TransparencyMask_enum]; }
        ResourceType& ExposureTexture() { return resources[Field::ExposureTexture_enum]; }
        ResourceType& BiasCurrentColorMask() { return resources[Field::BiasCurrentColorMask_enum]; }
        ResourceType& GBufferAlbedo() { return resources[Field::GBufferAlbedo_enum]; }
        ResourceType& GBufferRoughness() { return resources[Field::GBufferRoughness_enum]; }
        ResourceType& GBufferMetallic() { return resources[Field::GBufferMetallic_enum]; }
        ResourceType& GBufferSpecular() { return resources[Field::GBufferSpecular_enum]; }
        ResourceType& GBufferSubsurface() { return resources[Field::GBufferSubsurface_enum]; }
        ResourceType& GBufferNormals() { return resources[Field::GBufferNormals_enum]; }
        ResourceType& GBufferShadingModelId() { return resources[Field::GBufferShadingModelId_enum]; }
        ResourceType& GBufferMaterialId() { return resources[Field::GBufferMaterialId_enum]; }
        ResourceType& GBufferAttrib0() { return resources[Field::GBufferAttrib0_enum]; }
        ResourceType& GBufferAttrib1() { return resources[Field::GBufferAttrib1_enum]; }
        ResourceType& GBufferAttrib2() { return resources[Field::GBufferAttrib2_enum]; }
        ResourceType& GBufferAttrib3() { return resources[Field::GBufferAttrib3_enum]; }
        ResourceType& GBufferAttrib4() { return resources[Field::GBufferAttrib4_enum]; }
        ResourceType& GBufferAttrib5() { return resources[Field::GBufferAttrib5_enum]; }
        ResourceType& GBufferAttrib6() { return resources[Field::GBufferAttrib6_enum]; }
        ResourceType& GBufferAttrib7() { return resources[Field::GBufferAttrib7_enum]; }
        ResourceType& GBufferAttrib8() { return resources[Field::GBufferAttrib8_enum]; }
        ResourceType& GBufferAttrib9() { return resources[Field::GBufferAttrib9_enum]; }
        ResourceType& GBufferAttrib10() { return resources[Field::GBufferAttrib10_enum]; }
        ResourceType& GBufferAttrib11() { return resources[Field::GBufferAttrib11_enum]; }
        ResourceType& GBufferAttrib12() { return resources[Field::GBufferAttrib12_enum]; }
        ResourceType& GBufferAttrib13() { return resources[Field::GBufferAttrib13_enum]; }
        ResourceType& GBufferAttrib14() { return resources[Field::GBufferAttrib14_enum]; }
        ResourceType& GBufferAttrib15() { return resources[Field::GBufferAttrib15_enum]; }
        ResourceType& MotionVectors3D() { return resources[Field::MotionVectors3D_enum]; }
        ResourceType& IsParticleMask() { return resources[Field::IsParticleMask_enum]; }
        ResourceType& AnimatedTextureMask() { return resources[Field::AnimatedTextureMask_enum]; }
        ResourceType& DepthHighRes() { return resources[Field::DepthHighRes_enum]; }
        ResourceType& MotionVectorsReflection() { return resources[Field::MotionVectorsReflection_enum]; }

        ResourceType& operator[](size_t index) {
            if (index >= Field::length_enum) {
                throw std::out_of_range("Invalid index");
            }
            return resources[index];
        }

        const ResourceType& operator[](size_t index) const {
            if (index >= Field::length_enum) {
                throw std::out_of_range("Invalid index");
            }
            return resources[index];
        }
    };

    typedef DLSS_Resources_Holder<ID3D11Resource*> D3D11_DLSSResources;
    typedef DLSS_Resources_Holder<ID3D12Resource*> D3D12_DLSSResources;
    typedef DLSS_Resources_Holder<NVSDK_NGX_Resource_VK*> VK_DLSSResources;
}

std::wostream& operator<<(std::wostream& os, const CyberTypes::SystemInfo& systemInfo);
std::wostream& operator<<(std::wostream& os, const CyberTypes::RTC& rtc);
std::wostream& operator<<(std::wostream& os, const CyberTypes::CoreInfo& coreInfo);
std::wostream& operator<<(std::wostream& os, const CyberTypes::HighPerformanceCounterInfo& counterInfo);

template <typename T1, typename T2>
void stringify_args_helper(T1& os, const T2& str) {
    os << str << L" ";
}

template <typename T1>
void stringify_args_helper(T1& os, const char str[]) {
    os << CyberTypes::stringToWstring(str) << L" ";
}

template <typename T1>
void stringify_args_helper(T1& os, const wchar_t str[]) {
    os << str << L" ";
}

template <typename... Args>
std::wstring stringify_args(const Args&... args) {
    std::wostringstream ss;
    (stringify_args_helper(ss, args), ...);
    return ss.str();
}