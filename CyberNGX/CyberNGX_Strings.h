#include "pch.h"

#ifndef CyberNGX_Strings_H
#define CyberNGX_Strings_H

#define CyberNGX_Strings_Macros(wrapper_macro) \
        wrapper_macro(NVSDK_NGX_EParameter_Reserved00), \
        wrapper_macro(NVSDK_NGX_EParameter_SuperSampling_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_InPainting_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSuperResolution_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_SlowMotion_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_VideoSuperResolution_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_Reserved06), \
        wrapper_macro(NVSDK_NGX_EParameter_Reserved07), \
        wrapper_macro(NVSDK_NGX_EParameter_Reserved08), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSignalProcessing_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSuperResolution_ScaleFactor_2_1), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSuperResolution_ScaleFactor_3_1), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSuperResolution_ScaleFactor_3_2), \
        wrapper_macro(NVSDK_NGX_EParameter_ImageSuperResolution_ScaleFactor_4_3), \
        wrapper_macro(NVSDK_NGX_EParameter_NumFrames), \
        wrapper_macro(NVSDK_NGX_EParameter_Scale), \
        wrapper_macro(NVSDK_NGX_EParameter_Width), \
        wrapper_macro(NVSDK_NGX_EParameter_Height), \
        wrapper_macro(NVSDK_NGX_EParameter_OutWidth), \
        wrapper_macro(NVSDK_NGX_EParameter_OutHeight), \
        wrapper_macro(NVSDK_NGX_EParameter_Sharpness), \
        wrapper_macro(NVSDK_NGX_EParameter_Scratch), \
        wrapper_macro(NVSDK_NGX_EParameter_Scratch_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_EvaluationNode), \
        wrapper_macro(NVSDK_NGX_EParameter_Input1), \
        wrapper_macro(NVSDK_NGX_EParameter_Input1_Format), \
        wrapper_macro(NVSDK_NGX_EParameter_Input1_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_Input2), \
        wrapper_macro(NVSDK_NGX_EParameter_Input2_Format), \
        wrapper_macro(NVSDK_NGX_EParameter_Input2_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_Color), \
        wrapper_macro(NVSDK_NGX_EParameter_Color_Format), \
        wrapper_macro(NVSDK_NGX_EParameter_Color_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_Albedo), \
        wrapper_macro(NVSDK_NGX_EParameter_Output), \
        wrapper_macro(NVSDK_NGX_EParameter_Output_Format), \
        wrapper_macro(NVSDK_NGX_EParameter_Output_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_Reset), \
        wrapper_macro(NVSDK_NGX_EParameter_BlendFactor), \
        wrapper_macro(NVSDK_NGX_EParameter_MotionVectors), \
        wrapper_macro(NVSDK_NGX_EParameter_Rect_X), \
        wrapper_macro(NVSDK_NGX_EParameter_Rect_Y), \
        wrapper_macro(NVSDK_NGX_EParameter_Rect_W), \
        wrapper_macro(NVSDK_NGX_EParameter_Rect_H), \
        wrapper_macro(NVSDK_NGX_EParameter_MV_Scale_X), \
        wrapper_macro(NVSDK_NGX_EParameter_MV_Scale_Y), \
        wrapper_macro(NVSDK_NGX_EParameter_Model), \
        wrapper_macro(NVSDK_NGX_EParameter_Format), \
        wrapper_macro(NVSDK_NGX_EParameter_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_EParameter_ResourceAllocCallback), \
        wrapper_macro(NVSDK_NGX_EParameter_BufferAllocCallback), \
        wrapper_macro(NVSDK_NGX_EParameter_Tex2DAllocCallback), \
        wrapper_macro(NVSDK_NGX_EParameter_ResourceReleaseCallback), \
        wrapper_macro(NVSDK_NGX_EParameter_CreationNodeMask), \
        wrapper_macro(NVSDK_NGX_EParameter_VisibilityNodeMask), \
        wrapper_macro(NVSDK_NGX_EParameter_PreviousOutput), \
        wrapper_macro(NVSDK_NGX_EParameter_MV_Offset_X), \
        wrapper_macro(NVSDK_NGX_EParameter_MV_Offset_Y), \
        wrapper_macro(NVSDK_NGX_EParameter_Hint_UseFireflySwatter), \
        wrapper_macro(NVSDK_NGX_EParameter_Resource_Width), \
        wrapper_macro(NVSDK_NGX_EParameter_Resource_Height), \
        wrapper_macro(NVSDK_NGX_EParameter_Depth), \
        wrapper_macro(NVSDK_NGX_EParameter_DLSSOptimalSettingsCallback), \
        wrapper_macro(NVSDK_NGX_EParameter_PerfQualityValue), \
        wrapper_macro(NVSDK_NGX_EParameter_RTXValue), \
        wrapper_macro(NVSDK_NGX_EParameter_DLSSMode), \
        wrapper_macro(NVSDK_NGX_EParameter_DeepResolve_Available), \
        wrapper_macro(NVSDK_NGX_EParameter_Deprecated_43), \
        wrapper_macro(NVSDK_NGX_EParameter_OptLevel), \
        wrapper_macro(NVSDK_NGX_EParameter_IsDevSnippetBranch), \
        wrapper_macro(NVSDK_NGX_EParameter_DeepDVC_Avalilable), \
        wrapper_macro(NVSDK_NGX_Parameter_OptLevel), \
        wrapper_macro(NVSDK_NGX_Parameter_IsDevSnippetBranch), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_ScaleFactor), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_ScaleFactor), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_InPainting_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_SlowMotion_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_VideoSuperResolution_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepResolve_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_Available), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_InPainting_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_SlowMotion_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_VideoSuperResolution_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepResolve_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_FrameInterpolation_NeedsUpdatedDriver), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_InPainting_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_SlowMotion_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_VideoSuperResolution_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepResolve_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_FrameInterpolation_MinDriverVersionMajor), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_InPainting_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_SlowMotion_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_VideoSuperResolution_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepResolve_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_MinDriverVersionMinor), \
        wrapper_macro(NVSDK_NGX_Parameter_SuperSampling_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_InPainting_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_SlowMotion_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_VideoSuperResolution_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSignalProcessing_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepResolve_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_FrameInterpolation_FeatureInitResult), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_ScaleFactor_2_1), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_ScaleFactor_3_1), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_ScaleFactor_3_2), \
        wrapper_macro(NVSDK_NGX_Parameter_ImageSuperResolution_ScaleFactor_4_3), \
        wrapper_macro(NVSDK_NGX_Parameter_DeepDVC_Strength), \
        wrapper_macro(NVSDK_NGX_Parameter_NumFrames), \
        wrapper_macro(NVSDK_NGX_Parameter_Scale), \
        wrapper_macro(NVSDK_NGX_Parameter_Width), \
        wrapper_macro(NVSDK_NGX_Parameter_Height), \
        wrapper_macro(NVSDK_NGX_Parameter_OutWidth), \
        wrapper_macro(NVSDK_NGX_Parameter_OutHeight), \
        wrapper_macro(NVSDK_NGX_Parameter_Sharpness), \
        wrapper_macro(NVSDK_NGX_Parameter_Scratch), \
        wrapper_macro(NVSDK_NGX_Parameter_Scratch_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_Input1), \
        wrapper_macro(NVSDK_NGX_Parameter_Input1_Format), \
        wrapper_macro(NVSDK_NGX_Parameter_Input1_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_Input2), \
        wrapper_macro(NVSDK_NGX_Parameter_Input2_Format), \
        wrapper_macro(NVSDK_NGX_Parameter_Input2_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_Color), \
        wrapper_macro(NVSDK_NGX_Parameter_Color_Format), \
        wrapper_macro(NVSDK_NGX_Parameter_Color_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Color1), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Color2), \
        wrapper_macro(NVSDK_NGX_Parameter_Albedo), \
        wrapper_macro(NVSDK_NGX_Parameter_Output), \
        wrapper_macro(NVSDK_NGX_Parameter_Output_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Output1), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Output2), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Output3), \
        wrapper_macro(NVSDK_NGX_Parameter_Reset), \
        wrapper_macro(NVSDK_NGX_Parameter_BlendFactor), \
        wrapper_macro(NVSDK_NGX_Parameter_MotionVectors), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_MotionVectors1), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_MotionVectors2), \
        wrapper_macro(NVSDK_NGX_Parameter_Rect_X), \
        wrapper_macro(NVSDK_NGX_Parameter_Rect_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_Rect_W), \
        wrapper_macro(NVSDK_NGX_Parameter_Rect_H), \
        wrapper_macro(NVSDK_NGX_Parameter_MV_Scale_X), \
        wrapper_macro(NVSDK_NGX_Parameter_MV_Scale_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_Model), \
        wrapper_macro(NVSDK_NGX_Parameter_Format), \
        wrapper_macro(NVSDK_NGX_Parameter_SizeInBytes), \
        wrapper_macro(NVSDK_NGX_Parameter_ResourceAllocCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_BufferAllocCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_Tex2DAllocCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_ResourceReleaseCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_CreationNodeMask), \
        wrapper_macro(NVSDK_NGX_Parameter_VisibilityNodeMask), \
        wrapper_macro(NVSDK_NGX_Parameter_MV_Offset_X), \
        wrapper_macro(NVSDK_NGX_Parameter_MV_Offset_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_Hint_UseFireflySwatter), \
        wrapper_macro(NVSDK_NGX_Parameter_Resource_Width), \
        wrapper_macro(NVSDK_NGX_Parameter_Resource_Height), \
        wrapper_macro(NVSDK_NGX_Parameter_Resource_OutWidth), \
        wrapper_macro(NVSDK_NGX_Parameter_Resource_OutHeight), \
        wrapper_macro(NVSDK_NGX_Parameter_Depth), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Depth1), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Depth2), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSSOptimalSettingsCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSSGetStatsCallback), \
        wrapper_macro(NVSDK_NGX_Parameter_PerfQualityValue), \
        wrapper_macro(NVSDK_NGX_Parameter_RTXValue), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSSMode), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_Mode), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_OF_Preset), \
        wrapper_macro(NVSDK_NGX_Parameter_FI_OF_GridSize), \
        wrapper_macro(NVSDK_NGX_Parameter_Jitter_Offset_X), \
        wrapper_macro(NVSDK_NGX_Parameter_Jitter_Offset_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_Denoise), \
        wrapper_macro(NVSDK_NGX_Parameter_TransparencyMask), \
        wrapper_macro(NVSDK_NGX_Parameter_ExposureTexture), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Feature_Create_Flags), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Checkerboard_Jitter_Hack), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Normals), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Albedo), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Roughness), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_DiffuseAlbedo), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_SpecularAlbedo), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_IndirectAlbedo), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_SpecularMvec), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_DisocclusionMask), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Metallic), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Specular), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Subsurface), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_ShadingModelId), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_MaterialId), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_8), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_9), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_10), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_11), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_12), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_13), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_14), \
        wrapper_macro(NVSDK_NGX_Parameter_GBuffer_Atrrib_15), \
        wrapper_macro(NVSDK_NGX_Parameter_TonemapperType), \
        wrapper_macro(NVSDK_NGX_Parameter_FreeMemOnReleaseFeature), \
        wrapper_macro(NVSDK_NGX_Parameter_MotionVectors3D), \
        wrapper_macro(NVSDK_NGX_Parameter_IsParticleMask), \
        wrapper_macro(NVSDK_NGX_Parameter_AnimatedTextureMask), \
        wrapper_macro(NVSDK_NGX_Parameter_DepthHighRes), \
        wrapper_macro(NVSDK_NGX_Parameter_Position_ViewSpace), \
        wrapper_macro(NVSDK_NGX_Parameter_FrameTimeDeltaInMsec), \
        wrapper_macro(NVSDK_NGX_Parameter_RayTracingHitDistance), \
        wrapper_macro(NVSDK_NGX_Parameter_MotionVectorsReflection), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Enable_Output_Subrects), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Color_Subrect_Base_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Color_Subrect_Base_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Depth_Subrect_Base_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Depth_Subrect_Base_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_MV_SubrectBase_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_MV_SubrectBase_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Translucency_SubrectBase_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Translucency_SubrectBase_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Output_Subrect_Base_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Output_Subrect_Base_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Render_Subrect_Dimensions_Width), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Render_Subrect_Dimensions_Height), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Pre_Exposure), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Exposure_Scale), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Bias_Current_Color_Mask), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Bias_Current_Color_SubrectBase_X), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Input_Bias_Current_Color_SubrectBase_Y), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Indicator_Invert_Y_Axis), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Indicator_Invert_X_Axis), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_INV_VIEW_PROJECTION_MATRIX), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_CLIP_TO_PREV_CLIP_MATRIX), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Max_Render_Width), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Max_Render_Height), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Min_Render_Width), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Get_Dynamic_Min_Render_Height), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_DLAA), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_Quality), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_Balanced), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_Performance), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_UltraPerformance), \
        wrapper_macro(NVSDK_NGX_Parameter_DLSS_Hint_Render_Preset_UltraQuality)

#define CyberNGX_Strings_CONCATENATE(a, b) a##b

#define CyberNGX_Strings_MacroToEnum(name) CyberNGX_Strings_CONCATENATE(name, _enum)
#define CyberNGX_Strings_MacroNameString(name) std::string_view(#name)
#define CyberNGX_Strings_MacroContentsString(name) std::string_view(name)

#define CyberNGX_Strings_ENUM_NAME(name) CyberNGX_Strings_CONCATENATE(##name, _enum)


#define CyberNGX_Strings_Headers(name) \
        enum CyberNGX_Strings_CONCATENATE(name, _enum) { CyberNGX_Strings_Macros(CyberNGX_Strings_ENUM_NAME), COUNT_enum }; \
        constexpr static std::string_view CyberNGX_Strings_CONCATENATE(name, _macroname)[] { ( CyberNGX_Strings_Macros(CyberNGX_Strings_MacroNameString) ) } ; \
        constexpr static std::string_view CyberNGX_Strings_CONCATENATE(name, _macrocontent)[] { ( CyberNGX_Strings_Macros(CyberNGX_Strings_MacroContentsString) ) };



#include <unordered_map>

namespace NGX_Strings {
    static struct NGX_Enum_Strings {
        CyberNGX_Strings_Headers(NGX_Strings);

        enum InitStatus { cold, warming, hot};

        InitStatus initstatus{cold};

        std::unordered_map<std::string_view, NGX_Strings_enum> map_macroname_to_enum;

        std::unordered_map<std::string_view, NGX_Strings_enum> map_macrocontent_to_enum;

        void populate_maps();

        NGX_Enum_Strings();

        NGX_Strings_enum getEnumFromMacroName(const std::string_view& value);

        NGX_Strings_enum getEnumFromMacroContents(const std::string_view& value);

        std::string_view getMacroNameFromEnum(NGX_Strings_enum value);

        std::string_view getMacroContentFromEnum(NGX_Strings_enum value);
    } Strings_Converter;


}

#endif