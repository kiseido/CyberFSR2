#pragma once

#include "Common.h"
#include <bitset>

namespace CyberInterposer
{
	typedef void* Raw_NVNGX_Parameter[sizeof(NVSDK_NGX_Parameter)];

	union PFN_Table_NVNGX_Parameter_Union_P
	{
		Raw_NVNGX_Parameter* pointers;
		NVSDK_NGX_Parameter* param;
		PFN_Table_NVNGX_Parameter_Union_P(NVSDK_NGX_Parameter*);
		PFN_Table_NVNGX_Parameter_Union_P();
	};

	struct CI_Parameter : public NVSDK_NGX_Parameter
	{
		void Set(const char* InName, unsigned long long InValue) override;
		void Set(const char* InName, float InValue) override;
		void Set(const char* InName, double InValue) override;
		void Set(const char* InName, unsigned int InValue) override;
		void Set(const char* InName, int InValue) override;
		void Set(const char* InName, void* InValue) override;
		void Set(const char* InName, ID3D11Resource* InValue) override;
		void Set(const char* InName, ID3D12Resource* InValue) override;


		NVSDK_NGX_Result Get(const char* InName, unsigned long long* OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, float* OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, double* OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, unsigned int* OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, int* OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, void** OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, ID3D11Resource** OutValue) const override;
		NVSDK_NGX_Result Get(const char* InName, ID3D12Resource** OutValue) const override;

		void Reset() override;

		static NVSDK_NGX_Result CALLBACK GetOptimalSettingsCallback(CI_Parameter* inParam);
		static NVSDK_NGX_Result CALLBACK GetStatsCallback(CI_Parameter* inParam);

		CI_Parameter(NVSDK_NGX_Parameter*);

		CI_Parameter();

	private:

		template<typename T>
		NVSDK_NGX_Result GetHelper(const char* InName, T* OutValue) const;

		template<typename T>
		void SetHelper(const char* InName, T InValue);


		using GetOptimalSettingsCallbackType = NVSDK_NGX_Result(*)(NVSDK_NGX_Parameter* inParam);
		using GetStatsCallbackType = NVSDK_NGX_Result(*)(NVSDK_NGX_Parameter* inParam);

	public:

		mutable PFN_Table_NVNGX_Parameter_Union_P wrapped = PFN_Table_NVNGX_Parameter_Union_P(nullptr);

		mutable GetOptimalSettingsCallbackType wrapped_GetOptimalSettingsCallback = nullptr;
		mutable GetStatsCallbackType wrapped_GetStatsCallback = nullptr;

	};

	struct CI_MGX_Parameter_StaticAlloc {
		static constexpr std::size_t PoolSize = 10000;

		CI_Parameter* claim() noexcept(false);
		CI_Parameter* claim(std::size_t number) noexcept(false);
		bool release(CI_Parameter* p) noexcept(false);
		bool release(CI_Parameter* p, std::size_t number) noexcept(false);

		CI_MGX_Parameter_StaticAlloc();

		static CI_MGX_Parameter_StaticAlloc GetParameters_depreciated;
		static CI_MGX_Parameter_StaticAlloc AllocateParameters;

	private:

		std::array<CI_Parameter, PoolSize> memoryPool;
		std::bitset<PoolSize> freeSlots;
		std::mutex allocatorMutex;
	};
}