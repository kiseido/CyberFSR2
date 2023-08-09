#include "pch.h"

#ifndef CyInt_NGX_Parameter
#define CyInt_NGX_Parameter

#include "Common.h"
#include <set>

namespace CyberInterposer
{
	typedef char Raw_NVNGX_Parameter[sizeof(NVSDK_NGX_Parameter)];

	union PFN_Table_NVNGX_Parameter_Union_P
	{
		Raw_NVNGX_Parameter* bytes;
		NVSDK_NGX_Parameter* param;
		PFN_Table_NVNGX_Parameter_Union_P(NVSDK_NGX_Parameter*);
	};

	struct CI_NGX_Parameter : public NVSDK_NGX_Parameter
	{
		virtual void Set(const char* InName, unsigned long long InValue) override;
		virtual void Set(const char* InName, float InValue) override;
		virtual void Set(const char* InName, double InValue) override;
		virtual void Set(const char* InName, unsigned int InValue) override;
		virtual void Set(const char* InName, int InValue) override;
		virtual void Set(const char* InName, ID3D11Resource* InValue) override;
		virtual void Set(const char* InName, ID3D12Resource* InValue) override;
		virtual void Set(const char* InName, void* InValue) override;
		virtual NVSDK_NGX_Result Get(const char* InName, unsigned long long* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, float* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, double* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, unsigned int* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, int* OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, ID3D11Resource** OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, ID3D12Resource** OutValue) const override;
		virtual NVSDK_NGX_Result Get(const char* InName, void** OutValue) const override;
		virtual void Reset() override;

		PFN_Table_NVNGX_Parameter_Union_P wrapped;

		CI_NGX_Parameter(NVSDK_NGX_Parameter*);

		CI_NGX_Parameter();
	};

	struct CI_MGX_Parameter_StaticAlloc {
		static constexpr std::size_t PoolSize = 10000;

		CI_NGX_Parameter* claim() noexcept(false);
		CI_NGX_Parameter* claim(std::size_t number) noexcept(false);
		bool release(CI_NGX_Parameter* p) noexcept(false);
		bool release(CI_NGX_Parameter* p, std::size_t number) noexcept(false);

		CI_MGX_Parameter_StaticAlloc();

		static CI_MGX_Parameter_StaticAlloc GetParameters_depreciated;
		static CI_MGX_Parameter_StaticAlloc AllocateParameters;

	private:

		std::array<CI_NGX_Parameter, PoolSize> memoryPool;
		std::set<std::size_t> freeSlots;
		std::mutex allocatorMutex;
	};
}


#endif