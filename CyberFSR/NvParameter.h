#pragma once
#include "pch.h"

#include <stdexcept>
#include <array>
#include <variant>
#include <limits>

namespace Hyper_NGX {

	struct TickerCode_t {
		size_t external_ticker = 0;
		size_t internal_ticker = 0;
	};

	using MacroStrings_enum_t = NGX_Strings::MacroStrings_enum_t;

	using InputVariable_t = std::variant<int, unsigned int, float, double, long, long long, unsigned long, unsigned long long, long double, void*, ID3D11Resource*, ID3D12Resource*>;

	struct CallEvent_t {
		enum call_type_t {
			error = 0, set = 8, get = 32, reset = 64, GetOptimalSettings = 128
		} callType;

		MacroStrings_enum_t key;
		InputVariable_t value;
		TickerCode_t request_timestep;
	};

	struct Handler_t {
		enum HandlerStatus_t { error, consumed, unconsumed };

		struct HandlerHelper {
			HandlerStatus_t status;
			int returnCode;
		};

		typedef HandlerHelper(*HandlerFunction_t)(ParameterDB_t&, CallEvent_t&);

		HandlerFunction_t ApplyFunc;

		Handler_t(HandlerFunction_t func = nullptr) : ApplyFunc(func) {};
	};

	struct HandlerDB_t {
	public:
		std::multimap<NGX_Strings::MacroStrings_enum_t, Handler_t> handlers;

		void addHandlerLogic(NGX_Strings::MacroStrings_enum_t, Handler_t);

		Handler_t::HandlerHelper Apply(ParameterDB_t&, CallEvent_t&);
	};

	struct ParameterDB_t {
	public:
		using ParameterCallHistory_t = std::vector<CallEvent_t>;

		using ValueCurrent_t = std::unordered_map<MacroStrings_enum_t, InputVariable_t>;
		using ValueHistory_t = std::multimap<MacroStrings_enum_t, CallEvent_t>;

		struct IncrementTimeStepHelper_t {
			TickerCode_t oldStep;
			TickerCode_t newStep;
		};
	private:
		ValueHistory_t value_history;
		ValueCurrent_t value_current;
		mutable std::mutex mtx;
		TickerCode_t current;
		ParameterCallHistory_t requestHistory;

		HandlerDB_t handlers;

		IncrementTimeStepHelper_t incrementInternalTimeStep();

	public:
		ParameterDB_t();
		TickerCode_t getCurrentTimeStep() const;
		IncrementTimeStepHelper_t incrementExternalTimeStep();

		void Set(const char* name, const InputVariable_t value);
		InputVariable_t Get(const char* name);

		void Set(NGX_Strings::MacroStrings_enum_t, const InputVariable_t value);
		InputVariable_t Get(NGX_Strings::MacroStrings_enum_t);

		void addHandlerLogic(NGX_Strings::MacroStrings_enum_t, Handler_t);
	};

	struct Parameter : NVSDK_NGX_Parameter
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

		Hyper_NGX::ParameterDB_t* parameterDB;

		static NGX_Strings::MacroStrings_enum_t stringToEnum(const char* name);

		NVSDK_NGX_Result GetOptimalSettingsCallback();
		NVSDK_NGX_Result GetStatsCallback();
	};
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);