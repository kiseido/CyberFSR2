#pragma once
#include "pch.h"

#include <stdexcept>
#include <array>
#include <variant>
#include <limits>

struct FSR2_Settings {
	enum ReactiveMaskState {
		Game_Defined,
		Auto_Mask,
		Disabled
	};
	ReactiveMaskState ReactiveMaskState;

};

namespace Hyper_NGX_DB {

	struct TickerCode {
		size_t external_ticker = 0;
		size_t internal_ticker = 0;
	};

	using NGX_Strings_enum = NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum;

	using NvParameterValue = std::variant<int, unsigned int, float, double, long, long long, unsigned long, unsigned long long, long double, void*, ID3D11Resource*, ID3D12Resource*>;

	struct ParameterCall {
		enum call_type {
			error = 0, set = 8, get = 32
		} callType;
		NGX_Strings_enum key;
		NvParameterValue value;
		TickerCode request_timestep;
	};

	class ParamStrategy {
	public:
		enum StrategyAction { error, consumed, unconsumed, send_to_db };
		virtual StrategyAction Set(Hyper_NGX_ParameterDB&, ParameterCall&) = 0;
		virtual StrategyAction Get(Hyper_NGX_ParameterDB&, ParameterCall&) = 0;
	};

	class StrategyDB {
	public:
		std::multimap<NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum, ParamStrategy> strategies;

		void addStrat(NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum, ParamStrategy*);

		ParamStrategy::StrategyAction Set(Hyper_NGX_ParameterDB&, ParameterCall&);
		ParamStrategy::StrategyAction Get(Hyper_NGX_ParameterDB&, ParameterCall&);
	};

	class Hyper_NGX_ParameterDB {
	public:


		struct ScribedValue {
			NvParameterValue value;
			TickerCode tick;
		};
		using ParameterCallHistory = std::vector<ParameterCall>;

		using ValueCurrent = std::unordered_map<NGX_Strings_enum, ScribedValue>;
		using ValueHistory = std::multimap<NGX_Strings_enum, ScribedValue>;

		struct incrementTimeStepHelper {
			TickerCode oldStep;
			TickerCode newStep;
		};
	private:
		ValueHistory value_history;
		ValueCurrent value_current;
		mutable std::mutex mtx;
		TickerCode currentTimeStep;
		ParameterCallHistory requestHistory;

		incrementTimeStepHelper incrementInternalTimeStep();

	public:
		Hyper_NGX_ParameterDB();
		TickerCode getCurrentTimeStep() const;
		incrementTimeStepHelper incrementExternalTimeStep();

		void Set(const char* name, const NvParameterValue value);
		std::optional<NvParameterValue> Get(const char* name);
	};

}





struct Hyper_NGX_Parameter : NVSDK_NGX_Parameter
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

	Hyper_NGX_DB::Hyper_NGX_ParameterDB* parameterDB;

	static NGX_Strings::NGX_Enum_Strings::NGX_Strings_enum stringToEnum(const char* name);
};


