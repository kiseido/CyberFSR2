#include "pch.h"
#include "NGX_Interposer.h"

using namespace CyberInterposer;

bool CyberInterposer::PFN_Table_T::LoadDLL(LPCWSTR inputFileName, bool populateChildren)
{
    CyberLogArgs(inputFileName, populateChildren);

    HMODULE hModule = LoadLibraryW(inputFileName);

    return LoadDLL(hModule, populateChildren);
}