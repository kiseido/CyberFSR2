#pragma once
#include "pch.h"

#include <stdexcept>
#include <array>
#include <variant>
#include <limits>

namespace Hyper_NGX {

	struct InstructionCounter_t {
		size_t external_counter = 0;
		size_t internal_counter = 0;
	};

	using MacroStrings_enum_t = NGX_Strings::MacroStrings_enum_t;

	using InputVariable_t = std::variant<int, unsigned int, float, double, long, long long, unsigned long, unsigned long long, long double, void*, ID3D11Resource*, ID3D12Resource*>;

	struct CallEvent_t {
		enum call_type_t {
			error = 0b0,
			UnsignedLongLong_ = 0b1 << 0,
			Float_ = 0b1 << 1,
			Double_ = 0b1 << 2,
			UnsignedInt_ = 0b1 << 3,
			Int_ = 0b1 << 4,
			VoidPointer_ = 0b1 << 5,
			D3D11Resource_ = 0b1 << 6,
			D3D12Resource_ = 0b1 << 7,
			VkResource_ = 0b1 << 8,
			set = 0b1 << 12,
			get = 0b1 << 13,
			reset = 0b1 << 14,
			GetOptimalSettings = 0b1 << 15,
			GetStats = 0b1 << 16
		};

		static std::vector<call_type_t> unpackTypes(call_type_t);
		static call_type_t packTypes(const std::vector<call_type_t>&);

		bool addType(call_type_t);
		bool hasType(call_type_t);
		bool removeType(call_type_t);

		call_type_t callType;
		MacroStrings_enum_t key;
		InputVariable_t value;
		InstructionCounter_t request_timestep;
	};

	struct Handler_t {
		enum HandlerStatus_t { error, consumed, unconsumed };

		struct HandlerHelper {
			HandlerStatus_t status;
			int returnCode;
		};

		typedef HandlerHelper(*HandlerFunction_t)(ParameterDB_t&, CallEvent_t&);

		HandlerFunction_t ApplyFunc;

		Handler_t(HandlerFunction_t func) : ApplyFunc(func) {};
	};

	struct HandlerDB_t {
		std::multimap<NGX_Strings::MacroStrings_enum_t, Handler_t> handlers;

		void addHandlerLogic(NGX_Strings::MacroStrings_enum_t, Handler_t);

		Handler_t::HandlerHelper Apply(ParameterDB_t&, CallEvent_t&);
	};

	struct ParameterDB_t {

		using ParameterCallHistory_t = std::vector<CallEvent_t>;

		using ValueCurrent_t = std::unordered_map<MacroStrings_enum_t, InputVariable_t>;
		using ValueHistory_t = std::multimap<MacroStrings_enum_t, CallEvent_t>;

		struct IncrementTimeStepHelper_t {
			InstructionCounter_t oldStep;
			InstructionCounter_t newStep;
		};

		mutable std::mutex mtx;

		mutable ValueHistory_t value_history;
		mutable ParameterCallHistory_t requestHistory;

		ValueCurrent_t value_current;
		InstructionCounter_t current;

		HandlerDB_t handlers;

		IncrementTimeStepHelper_t incrementInternalTimeStep();


		ParameterDB_t();
		InstructionCounter_t getCurrentTimeStep() const;
		IncrementTimeStepHelper_t incrementExternalTimeStep();

		void Set(NGX_Strings::MacroStrings_enum_t, const InputVariable_t value);
		std::optional<InputVariable_t> Get(NGX_Strings::MacroStrings_enum_t) const;

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

		Hyper_NGX::ParameterDB_t parameterDB;

		static NGX_Strings::MacroStrings_enum_t stringToEnum(const char* name);

		NVSDK_NGX_Result GetOptimalSettingsCallback();
		NVSDK_NGX_Result GetStatsCallback();
	};

	template <typename T>
	std::optional<T> ConvertVariant(const Hyper_NGX::InputVariable_t& var);
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);