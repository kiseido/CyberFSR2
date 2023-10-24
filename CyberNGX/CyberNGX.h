#pragma once


#include "CyberTypes.h"
#include "NGX_PFN_Definitions.h"
#include "Utils.h"
#include "CyberNGX_Strings.h"

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_vk.h>

#define Expose_API __declspec(dllexport)
#define C_Declare __cdecl

namespace CyberNGX {
	template <typename ResourceType>
	struct DLSSResources {
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

	typedef DLSSResources<ID3D11Resource*> D3D11_DLSSResources;
	typedef DLSSResources<ID3D12Resource*> D3D12_DLSSResources;
	typedef DLSSResources<NVSDK_NGX_Resource_VK*> VK_DLSSResources;
}