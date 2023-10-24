#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <wrl/wrappers/corewrappers.h>
#include <memory>
#include <vector>
#include <mutex>
#include <limits>
#include <string>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <stdexcept>



#include <d3d11.h>
#include <d3dcompiler.h>

#include <d3d12.h>
#include <DirectXMath.h>
#include <wrl/wrappers/corewrappers.h>
#include <memory>
#include <vector>
#include <mutex>
#include <limits>
#include <string>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <stdexcept>

#include <vulkan/vulkan.hpp>


#define NV_WINDOWS
#define NVSDK_NGX
#define NGX_ENABLE_DEPRECATED_GET_PARAMETERS
#define NGX_ENABLE_DEPRECATED_SHUTDOWN

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_vk.h>