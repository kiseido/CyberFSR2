#pragma once
#include "pch.h"

#include <stdexcept>
#include <array>
#include <variant>
#include <limits>

namespace Hyper_NGX_Parameter {

	struct InstructionCounter_t {
		size_t external_counter = 0;
		size_t internal_counter = 0;
	};

	struct IncrementCounterHelper_t {
		InstructionCounter_t oldStep;
		InstructionCounter_t newStep;
	};

	using MacroStrings_enum = NGX_Strings::MacroStrings_enum;

	using InputVariableVariants_t = std::variant<int, unsigned int, float, double, long, long long, unsigned long, unsigned long long, long double, void*, ID3D11Resource*, ID3D12Resource*>;

	struct InputVariable_t : public InputVariableVariants_t {

		InputVariable_t(const InputVariableVariants_t& internalValue) : InputVariableVariants_t(internalValue) {}

		template <typename T>
		T GetAsType() {
			if (std::holds_alternative<T>(*this)) {
				return std::get<T>(*this);
			}
			// Arithmetic to arithmetic
			else if constexpr (std::is_arithmetic_v<T> && std::is_arithmetic_v<std::decay_t<decltype(*this)>>) {
				return static_cast<T>(std::get<std::decay_t<decltype(*this)>>(*this));
			}
			// Any type to pointer or pointer to any type
			else if constexpr (std::is_pointer_v<T> || std::is_pointer_v<std::decay_t<decltype(*this)>>) {
				return reinterpret_cast<T>(std::get<std::decay_t<decltype(*this)>>(*this));
			}
			else {
				throw std::runtime_error("Invalid conversion.");
			}
		}
	};


	struct CallEvent_t {
		enum CallType_enum : uint16_t {
			error = 0b0,
			UnsignedLongLong_ = 1,
			Float_ = 2,
			Double_ = 3,
			UnsignedInt_ = 4,
			Int_ = 5,
			VoidPointer_ = 6,
			D3D11Resource_ = 7,
			D3D12Resource_ = 8,
			VkResource_ = 9,
			set = 0b1 << 11,
			get = 0b1 << 12,
			reset = 0b1 << 13,
			GetOptimalSettings = 0b1 << 14,
			GetStats = 0b1 << 15
		};
	private:
		CallType_enum callType;
		MacroStrings_enum key;
		InputVariable_t internalValue;
		InstructionCounter_t request_timestep;
	public:
		bool addType(CallType_enum);
		bool hasType(CallType_enum);
		bool removeType(CallType_enum);

		static std::vector<CallType_enum> unpackTypes(CallType_enum);
		static CallType_enum packTypes(const std::vector<CallType_enum>&);
	};


	enum HandlerStatus_enum : UINT8 { error_uninited = 0, consumed = 0b11110000, unconsumed = 0b00001111 };


	struct HandlerHelper_t {
		HandlerStatus_enum status = error_uninited;
		int returnCode = 0;
	};

	typedef HandlerHelper_t(*HandlerFunction_t)(const HandlerInstance_t&, ParameterDB_t&, const CallEvent_t&);

	struct HandlerInstance_t {
		using HandlerId_t = Util::GenericId<4>;
	public:
		const CallEvent_t compatible_with;
		const HandlerId_t id;
		const HandlerFunction_t ApplyFunc;

		HandlerInstance_t(HandlerFunction_t func, HandlerId_t id, CallEvent_t compat) : ApplyFunc(func), compatible_with(compat), id(id) {};
	};

	struct HandlerDB_t {
		using HandlerMap_t = std::multimap<NGX_Strings::MacroStrings_enum, HandlerInstance_t>;
	private:
		mutable std::mutex mtx;
		HandlerMap_t handlers;
	public:
		bool addHandlerLogic(NGX_Strings::MacroStrings_enum, HandlerInstance_t);
		int removeHandlerLogic(NGX_Strings::MacroStrings_enum key, HandlerInstance_t::HandlerId_t id);

		HandlerHelper_t Apply(ParameterDB_t&, CallEvent_t&);

		Util::SharedLockContainer<HandlerMap_t&> getMap_InternalExclusive();
	};

	struct ValueDB_t {
		using ValueCurrent_t = std::unordered_map<MacroStrings_enum, InputVariable_t>;
		using ValueHistory_t = std::multimap<MacroStrings_enum, CallEvent_t>;
	private:
		mutable std::mutex mtx;
		ValueCurrent_t value_current;
		ValueHistory_t value_history;
	public:
		void Set(NGX_Strings::MacroStrings_enum, const InputVariable_t internalValue);
		std::optional<InputVariable_t> Get(NGX_Strings::MacroStrings_enum) const;

		Util::SharedLockContainer<const ValueHistory_t&> getHistory_InternalExclusive();
	};

	struct ParameterDB_t {
		using CallHistory_t = std::vector<CallEvent_t>;
	private:
		mutable std::mutex mtx;
		HandlerDB_t handlers;
		ValueDB_t values;
		mutable CallHistory_t requestHistory;
		mutable InstructionCounter_t current_counter;

	public:
		ParameterDB_t();

		void Set(NGX_Strings::MacroStrings_enum, const InputVariable_t internalValue);
		std::optional<InputVariable_t> Get(NGX_Strings::MacroStrings_enum) const;

		InstructionCounter_t getCurrentTimeStep() const;
		IncrementCounterHelper_t incrementInternalTimeStep();
		IncrementCounterHelper_t incrementExternalTimeStep();

		const ValueDB_t& getValues_Internal();
		const CallHistory_t& getCallHistory_Internal();

		Util::SharedLockContainer<ValueDB_t&> getValues_InternalExclusive();
		Util::SharedLockContainer<const CallHistory_t&> getCallHistory_InternalExclusive();
		Util::SharedLockContainer<HandlerDB_t&> getHandlers_InternalExclusive();
	};


	struct Parameter : public NVSDK_NGX_Parameter
	{
		using ParameterId_t = Util::GenericId<9>;
	private:
		ParameterId_t HyperId = L"CyberFSR";
		Hyper_NGX_Parameter::ParameterDB_t parameterDB;

	public:
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

		NVSDK_NGX_Result GetOptimalSettingsCallback();
		NVSDK_NGX_Result GetStatsCallback();

		static Parameter* convertPointerIfValid(NVSDK_NGX_Parameter*);
		static NGX_Strings::MacroStrings_enum stringToEnum(const char* name);
	};

	class ParameterFactory {
	private:
		std::unordered_map<Parameter*, std::unique_ptr<Parameter>> parameterMap;
		std::mutex mtx;

	public:
		ParameterFactory();
		~ParameterFactory();

		Parameter* CreateParameter();
		void DestroyParameter(Parameter* parameter);
		void DestroyAllParameters();

	};
}

NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetOptimalSettingsCallback(NVSDK_NGX_Parameter* InParams);
NVSDK_NGX_Result NVSDK_CONV NVSDK_NGX_DLSS_GetStatsCallback(NVSDK_NGX_Parameter* InParams);