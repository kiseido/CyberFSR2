#pragma once
#include "pch.h"
#include "CommonStuff.h"

namespace CyberFSR 
{
	enum class Error_Resilient_Boolean;
	enum class Trinary;
	enum class SharpnessRangeModifier;
	enum class ViewMethod;
	enum class UpscalingProfile;

	class Config
	{
	public:
		Config(std::string fileName);

//   ██████╗ ███████╗███╗   ██╗███████╗██████╗  █████╗ ██╗     
//  ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔══██╗██╔══██╗██║     
//  ██║  ███╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝███████║██║     
//  ██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██║     
//  ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║███████╗
//   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
//                                                             
		bool DoEngineSpecific = true;

		// Upscale type
		CyberFSR::UpscalingProfile UpscalerProfile;

		// Quality Divisor
		float Divisor_Auto;
		float Divisor_UltraQuality;
		float Divisor_Quality;
		float Divisor_Balanced;
		float Divisor_Performance;
		float Divisor_UltraPerformance;

		//  Render Resolution Overrides
		ScreenDimensions Resolution_Auto;
		ScreenDimensions Resolution_UltraQuality;
		ScreenDimensions Resolution_Quality;
		ScreenDimensions Resolution_Balanced;
		ScreenDimensions Resolution_Performance;
		ScreenDimensions Resolution_UltraPerformance;

		//  Render Resolution Overrides
		ScreenDimensions FPSTarget_Auto;
		ScreenDimensions FPSTarget_UltraQuality;
		ScreenDimensions FPSTarget_Quality;
		ScreenDimensions FPSTarget_Balanced;
		ScreenDimensions FPSTarget_Performance;
		ScreenDimensions FPSTarget_UltraPerformance;

//   ██████╗██╗   ██╗███████╗████████╗ ██████╗ ███╗   ███╗               
//  ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗████╗ ████║               
//  ██║     ██║   ██║███████╗   ██║   ██║   ██║██╔████╔██║█████╗         
//  ██║     ██║   ██║╚════██║   ██║   ██║   ██║██║╚██╔╝██║╚════╝         
//  ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝██║ ╚═╝ ██║               
//   ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝               
//                                                           
//  ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗                     
//  ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝                     
//  █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗                       
//  ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝                       
//  ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗                     
//  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝          
//                                                                                                                                                                                          
		// Depth
		std::optional<bool> DepthInverted;

		// Color
		std::optional<bool> AutoExposure;
		std::optional<bool> HDR;

		// Motion
		std::optional<bool> JitterCancellation;
		std::optional<bool> DisplayResolution;


		// Dynamic Scaler
		std::optional<bool> DynamicScalerEnabled;
		std::optional<float> FPSTarget;
		std::optional<float> FPSTargetMin;
		std::optional<float> FPSTargetMax;
		std::optional<float> FPSTargetResolutionMin;
		std::optional<float> FPSTargetResolutionMax;

		// View
		std::optional<ViewMethod> ViewHookMethod;
		std::optional<float> VerticalFOV;
		std::optional<float> NearPlane;
		std::optional<float> FarPlane;
		std::optional<bool> InfiniteFarPlane;

		// Hotfix for Steam Deck
		std::optional<bool> DisableReactiveMask;

		// Sharpening
		std::optional<bool> EnableSharpening;
		std::optional<float> Sharpness;
		std::optional<SharpnessRangeModifier> SharpnessRange;

		bool DilateMotionVectors = false;


//  ██╗   ██╗███╗   ██╗██████╗ ███████╗ █████╗ ██╗                       
//  ██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██║                       
//  ██║   ██║██╔██╗ ██║██████╔╝█████╗  ███████║██║█████╗                 
//  ██║   ██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██║██║╚════╝                 
//  ╚██████╔╝██║ ╚████║██║  ██║███████╗██║  ██║███████╗                  
//   ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝                  
//                                              
		// Unreal fixes
		Trinary UE_DilateMotionVectors = Trinary::ON;
		Trinary UE_DoNaviSceneColor = Trinary::ON;

		// Depth
		Trinary UE_DepthInverted = Trinary::TBD;

		// Motion
		Trinary UE_JitterCancellation = Trinary::TBD;
		Trinary UE_DisplayResolution = Trinary::TBD;

		// View
		Trinary UE_NearPlane = Trinary::TBD;
		Trinary UE_FarPlane = Trinary::TBD;
		Trinary UE_InfiniteFarPlane = Trinary::TBD;

		//Hotfix for Steam Deck
		Trinary UE_DisableReactiveMask = Trinary::TBD;

//  ██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗                             
//  ██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝                             
//  ██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝█████╗                        
//  ██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝ ╚════╝                        
//  ╚██████╔╝██║ ╚████║██║   ██║      ██║                                
//   ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝                                
//                                          
		// Depth
		Trinary Unity_DepthInverted = Trinary::TBD;

		// Motion
		Trinary Unity_JitterCancellation = Trinary::TBD;
		Trinary Unity_DisplayResolution = Trinary::TBD;

		// View
		Trinary Unity_NearPlane = Trinary::TBD;
		Trinary Unity_FarPlane = Trinary::TBD;
		Trinary Unity_InfiniteFarPlane = Trinary::TBD;

		//Hotfix for Steam Deck
		Trinary Unity_DisableReactiveMask = Trinary::TBD;

//   ██████╗ ███╗   ███╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗███████╗    
//  ██╔═══██╗████╗ ████║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝    
//  ██║   ██║██╔████╔██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝███████╗█████╗█████╗
//  ██║   ██║██║╚██╔╝██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝╚════╝
//  ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████║███████╗    
//   ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝    
//                                                                                  
		// Depth
		Trinary Omniverse_DepthInverted = Trinary::TBD;

		// Motion
		Trinary Omniverse_JitterCancellation = Trinary::TBD;
		Trinary Omniverse_DisplayResolution = Trinary::TBD;

		// View
		Trinary Omniverse_NearPlane = Trinary::TBD;
		Trinary Omniverse_FarPlane = Trinary::TBD;
		Trinary Omniverse_InfiniteFarPlane = Trinary::TBD;

		//Hotfix for Steam Deck
		Trinary Omniverse_DisableReactiveMask = Trinary::TBD;

		void Reload();

	private:
		CSimpleIniA ini;

		std::filesystem::path absoluteFileName;

		std::optional<std::string> readString(std::string section, std::string key, bool lowercase = false);
		std::optional<float> readFloat(std::string section, std::string key);
		std::optional<bool> readBool(std::string section, std::string key);
		std::optional<SharpnessRangeModifier> readSharpnessRange(std::string section, std::string key);
		std::optional<ViewMethod> readViewMethod(std::string section, std::string key);
		std::optional<UpscalingProfile> readUpscalingProfile(std::string section, std::string key);
		std::optional<std::pair<unsigned int, unsigned int>> readScreenDimensions(std::string section, std::string key);
	};
}

// Altus used a lovely website for the big text: https://patorjk.com/software/taag/#p=display&c=c%2B%2B&f=ANSI%20Shadow&t=engine%0Aoverrides 