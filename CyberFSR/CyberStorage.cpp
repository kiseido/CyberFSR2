#include "pch.h"
#include "CyberStorage.h"

constexpr CyberFSR::ModuleCode CyberFSR::GetPrimaryId(ModuleCode InValue)
{
	// magic number int size, 32bit
	constexpr unsigned int MAX_INT = 1 << 31;
	unsigned int i = MAX_INT;
	do
	{
		i = i >> 1;
	} while ((i & InValue) == 0 || i != 0);

	return (ModuleCode)i;
}

//struct NvBuffer {
//	static constexpr int ValueArrSize = 5000;
//	int head = 0;
//	int tail = 0;
//	CyberFSR::NvLogStruct values[ValueArrSize];
//};
//
//// Do not touch Nv_Log_Buffer, it's not thread safe
//NvBuffer Nv_Log_Buffer;

//void NVSDK_CONV NVSDK_NGX_AppLogCallback(const char* message, NVSDK_NGX_Logging_Level loggingLevel, NVSDK_NGX_Feature sourceComponent)
//{
//	const int index = Nv_Log_Buffer.head;
//	Nv_Log_Buffer.values[index] = { message, loggingLevel, sourceComponent };
//	Nv_Log_Buffer.head = (index + 1) % NvBuffer::ValueArrSize;
//}
