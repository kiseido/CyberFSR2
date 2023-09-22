#pragma once
#include "Config.h"



namespace Util
{
	std::filesystem::path ExePath();

	std::filesystem::path DllPath();

	double MillisecondsNow();

	float ConvertSharpness(float sharpness, std::optional<SharpnessRangeModifier> range);

	enum class Parameter
	{
		Invalid,

		//SuperSampling
		SuperSampling_ScaleFactor,
		SuperSampling_Available,
		SuperSampling_MinDriverVersionMajor,
		SuperSampling_MinDriverVersionMinor,
		SuperSampling_FeatureInitResult,
		SuperSampling_NeedsUpdatedDriver,
		//User settings stuff
		Width,
		Height,
		PerfQualityValue,
		RTXValue,
		FreeMemOnReleaseFeature,
		//Resolution stuff
		OutWidth,
		OutHeight,

		DLSS_Render_Subrect_Dimensions_Width,
		DLSS_Render_Subrect_Dimensions_Height,
		DLSS_Get_Dynamic_Max_Render_Width,
		DLSS_Get_Dynamic_Max_Render_Height,
		DLSS_Get_Dynamic_Min_Render_Width,
		DLSS_Get_Dynamic_Min_Render_Height,
		Sharpness,
		//Callbacks
		DLSSGetStatsCallback,
		DLSSOptimalSettingsCallback,

		//Render stuff
		CreationNodeMask,
		VisibilityNodeMask,
		DLSS_Feature_Create_Flags,
		DLSS_Enable_Output_Subrects,

		//D3D12 Buffers
		Color,
		MotionVectors,
		Depth,
		Output,
		TransparencyMask,
		ExposureTexture,
		DLSS_Input_Bias_Current_Color_Mask,
		Pre_Exposure,
		Exposure_Scale,

		Reset,
		MV_Scale_X,
		MV_Scale_Y,
		Jitter_Offset_X,
		Jitter_Offset_Y,

		//Dev Stuff
		SizeInBytes,
		OptLevel,
		IsDevSnippetBranch
	};

	Parameter NvParameterToEnum(const char* name);

	template<typename T>
	class SharedLockContainer {
	public:
		SharedLockContainer() = default;
		SharedLockContainer(const T& initial_value) : data_(initial_value) {}
		SharedLockContainer(T&& initial_value) : data_(std::move(initial_value)) {}

		class LockedData {
		public:
			LockedData(std::unique_lock<std::mutex>&& lock, T& data)
				: lock_(std::move(lock)), data_(data) {}

			T& get() {
				return data_;
			}

			// Optionally, overload the pointer and dereference operators for syntactic sugar
			T* operator->() {
				return &data_;
			}

			T& operator*() {
				return data_;
			}

		private:
			std::unique_lock<std::mutex> lock_;
			T& data_;
		};

		LockedData lockAndGet() {
			std::unique_lock<std::mutex> lock(mtx_);
			return LockedData(std::move(lock), data_);
		}

	private:
		std::mutex mtx_;
		T data_;
	};

	template <std::size_t N>
	struct GenericId {
		struct InternalValue_t { wchar_t chars[N]; };

		// Default constructor
		GenericId() {
			std::memset(internalValue.chars, 0, sizeof(internalValue.chars));
		}

		// Constructor accepting a wchar_t array of size N
		GenericId(const wchar_t(&initVal)[N]) {
			std::wcsncpy(internalValue.chars, initVal, N);
		}

		// Constructor accepting an InternalValue_t
		GenericId(const InternalValue_t& initVal) {
			std::wcsncpy(internalValue.chars, initVal.chars, N);
		}

		// Copy constructor (clonable)
		GenericId(const GenericId& other) {
			std::wcsncpy(internalValue.chars, other.internalValue.chars, N);
		}

		// Equality operator (comparable)
		bool operator==(const GenericId& other) const {
			if (this == &other) return true;
			return std::wcsncmp(internalValue.chars, other.internalValue.chars, N) == 0;
		}

		// Inequality operator (comparable)
		bool operator!=(const GenericId& other) const {
			return !(*this == other);
		}

		// Additional utility methods if needed
		const InternalValue_t& getValue() const {
			return internalValue;
		}

	private:
		InternalValue_t internalValue;
	};

};

inline void ThrowIfFailed(HRESULT hr)
{
	if (FAILED(hr))
	{
		// Set a breakpoint on this line to catch DirectX API errors
		throw std::exception();
	}
}