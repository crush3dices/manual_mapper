#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <bitset>

const char* dllFilePath = "D:\\Repos\\hexCS\\bin\\Release\\hexCS\\hexCS.dll";
const char* trgt = "csgo.exe";
int nSections;
IMAGE_SECTION_HEADER* sectionHeaders;

using std::cout;
using std::endl;
using std::hex;
using loadLibFun = HMODULE (__stdcall*)(LPCSTR);
using getProcAddrFun = FARPROC(__stdcall*)(HMODULE, LPCSTR);
using DLLMain = BOOL(APIENTRY* )(HMODULE, DWORD, LPVOID);

struct parameters
{
	getProcAddrFun gPADFPtr;				
	loadLibFun loadLibFunPtr;
	IMAGE_IMPORT_DESCRIPTOR* importTableP;
	DWORD imageBase;
	DWORD entry;
};

typedef struct
{
	unsigned Offset : 12;
	unsigned Type : 4;
}RELOCATION_ENTRY;

HANDLE openProcessByName(const char* procName, WORD accessRights)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (!strcmp(entry.szExeFile, procName))
			{
				CloseHandle(snapshot);
				return OpenProcess(accessRights, 0, entry.th32ProcessID);
			}
		} while (Process32Next(snapshot, &entry));
	}
	return NULL;
}

DWORD calcFileAddress(const DWORD& RVA)
{
	int found = -1;
	for (int i = 0; i < nSections; i++)
	{
		if (RVA < (sectionHeaders + i)->VirtualAddress)
		{
			found = i - 1;
			break;
		}
	}
	if (found == -1)
		found = nSections-1;

	return RVA - (sectionHeaders + found)->VirtualAddress + (sectionHeaders + found)->PointerToRawData;
}

DWORD __stdcall loadDll(LPVOID* input)
{
	parameters* params = (parameters*)input;
	for (; params->importTableP->OriginalFirstThunk != NULL; params->importTableP++)
	{
		char* name = (char*)(params->imageBase + params->importTableP->Name);
		HMODULE currDLLH = params->loadLibFunPtr(name);

		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(params->importTableP->FirstThunk + params->imageBase);
		for (; thunk->u1.AddressOfData != 0; thunk++)
		{
			if (thunk->u1.AddressOfData & 0x80000000) {
				DWORD Function = (DWORD)params->gPADFPtr(currDLLH,
					(LPCSTR)(thunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				thunk->u1.Function = Function;
			}
			else
			{
				thunk->u1.Function = (DWORD)params->gPADFPtr(currDLLH, (LPCSTR)((DWORD)thunk->u1.AddressOfData + 2 + params->imageBase));
				if (!thunk->u1.Function)
					return FALSE;
			}
		}
	}

	DLLMain EntryPoint = (DLLMain) params->entry;

	return EntryPoint((HMODULE)params->imageBase, DLL_PROCESS_ATTACH, NULL);
}

LPVOID readFile()
{
	HANDLE fileH = CreateFileA(dllFilePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	SIZE_T dllSize = GetFileSize(fileH, 0);
	LPVOID buffer = (IMAGE_DOS_HEADER*)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, dllSize);
	DWORD bytesRead = 0;
	if (!ReadFile(fileH, (LPVOID)buffer, dllSize, &bytesRead, NULL) || bytesRead != dllSize) {
		cout << "[ERROR] could not read the DLL file into buffer. " << bytesRead << " where read."<< endl;
		return 0;
	}
	return buffer;
}

int main()
{
	IMAGE_DOS_HEADER* dosHead = nullptr;
	IMAGE_NT_HEADERS* fileHeader = nullptr;
	IMAGE_BASE_RELOCATION* relocTable = nullptr,
		* curReloc = nullptr;
	HANDLE procHandle;

	dosHead = (IMAGE_DOS_HEADER*)readFile();
	fileHeader = (IMAGE_NT_HEADERS*)((DWORD)dosHead + dosHead->e_lfanew);

	nSections = fileHeader->FileHeader.NumberOfSections;
	sectionHeaders = (IMAGE_SECTION_HEADER*)((DWORD)&fileHeader->OptionalHeader + fileHeader->FileHeader.SizeOfOptionalHeader);
	DWORD imageBase = fileHeader->OptionalHeader.ImageBase;
	DWORD relocTableSize = fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD relocTableRVA = fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD importTableSize = fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD importTableRVA = fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD entryPointRVA = fileHeader->OptionalHeader.AddressOfEntryPoint;
	DWORD imageSize = fileHeader->OptionalHeader.SizeOfImage;

	procHandle = openProcessByName(trgt, PROCESS_ALL_ACCESS);

	if (!procHandle)
	{
		cout << "[ERROR] Target could either not be found or could not open a handle to it." << endl;
		delete[] dosHead;
		return 0;
	}
	DWORD realBase = (DWORD)VirtualAllocEx(procHandle, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!realBase)
	{
		cout << "[ERROR] failed to allocate Memory in the target process." << endl;
	}


	//--------------------------Relocations---------------------------------------------

	DWORD delta = realBase - imageBase;
	relocTable = (IMAGE_BASE_RELOCATION*)((DWORD)dosHead + calcFileAddress(relocTableRVA));
	curReloc = relocTable;
	DWORD relocEnd = (DWORD)relocTable + relocTableSize;

	for (; (DWORD)curReloc < relocEnd; curReloc = (IMAGE_BASE_RELOCATION*)((DWORD)curReloc + curReloc->SizeOfBlock))
	{
		DWORD blockEnd = (DWORD)curReloc + curReloc->SizeOfBlock;
		RELOCATION_ENTRY *relocEntry = (RELOCATION_ENTRY*)((DWORD)curReloc + sizeof(IMAGE_BASE_RELOCATION));	

		for (;(DWORD) relocEntry < blockEnd; relocEntry = (RELOCATION_ENTRY*)((DWORD)relocEntry + 2))
		{
			DWORD fixAddr = relocEntry->Offset + calcFileAddress(curReloc->VirtualAddress);
			switch (relocEntry->Type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGH:
				*(DWORD*)((DWORD)dosHead + fixAddr) = *(DWORD*)((DWORD)dosHead + fixAddr) + (delta & 0xff00);
				break;

			case IMAGE_REL_BASED_LOW:
				*(DWORD*)((DWORD)dosHead + fixAddr) = *(DWORD*)((DWORD)dosHead + fixAddr) + (delta & 0x00ff);
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD*)((DWORD)dosHead + fixAddr) = *(DWORD*)((DWORD)dosHead + fixAddr) + delta;
				break;
			default:
				cout << "[ERROR] while relocating the image. The reloctype: " << relocEntry->Type << " is unknown to this mapper. You might have to implement it!" << endl;
				CloseHandle(procHandle);
				return 0;
				break;
			}
		}
	}
	cout << "[+] Fixed all relocations." << endl;

	//--------------------------Map the Sections------------------------------

	DWORD sectionHeaderEnd = (DWORD)(sectionHeaders + nSections);
	IMAGE_SECTION_HEADER* curSectionHead = sectionHeaders;

	for (; (DWORD)curSectionHead < sectionHeaderEnd; ++curSectionHead)
	{
		DWORD vAddr = curSectionHead->VirtualAddress + realBase;
		char name[IMAGE_SIZEOF_SHORT_NAME + 1];
		_memccpy(name, curSectionHead->Name, NULL , IMAGE_SIZEOF_SHORT_NAME);
		name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		cout << "[+] written " << name << " to "<< hex << vAddr<< endl;
		DWORD buffLoc = (DWORD)dosHead + curSectionHead->PointerToRawData;
		SIZE_T nBytesWritten;
		SIZE_T bytesToCopy = min(curSectionHead->SizeOfRawData, curSectionHead->Misc.VirtualSize);

		WriteProcessMemory(procHandle, (LPVOID)vAddr, (LPCVOID)buffLoc, bytesToCopy, &nBytesWritten);

		if (nBytesWritten != min(curSectionHead->SizeOfRawData, curSectionHead->Misc.VirtualSize))
		{
			cout << "[ERROR] writing to the target process." << endl;
			delete[] dosHead;
			CloseHandle(procHandle);
			return 0;		
		}
	}

	cout << "[+] written the DLL to " << hex << realBase << endl;

	//--------------------------------polulate parameters---------------------------------------



	parameters params;
	params.importTableP = (IMAGE_IMPORT_DESCRIPTOR*)(importTableRVA + realBase);
	params.imageBase = realBase;
	params.entry = entryPointRVA + realBase;
	params.gPADFPtr = GetProcAddress;
	params.loadLibFunPtr = LoadLibraryA;
	SIZE_T nBytesWritten;
	HANDLE loaderDest;

	//---------------------------------load the loader-------------------------------------------------

	loaderDest = VirtualAllocEx(procHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	cout << "[+] allocated " << hex << 0x1000 << " bytes at " << hex << loaderDest << "." << endl;

	if (!loaderDest)
	{
		cout << "[ERROR] could not allocate memory for the laoder." << endl;
		delete[] dosHead;
		VirtualFreeEx(procHandle, (LPVOID)realBase, NULL, MEM_RELEASE);
		CloseHandle(procHandle);
		return 0;
	}

	WriteProcessMemory(procHandle, loaderDest, &params, sizeof(parameters), &nBytesWritten);

	if (nBytesWritten != sizeof(parameters))
	{
		cout << "[ERROR] writing the loader to the target." << endl;
		delete[] dosHead;
		VirtualFreeEx(procHandle, (LPVOID)realBase, NULL, MEM_RELEASE);
		CloseHandle(procHandle);
		return 0;
	}

	cout << "[+] written all parameters for the loader to " << hex << loaderDest << "." << endl;

	WriteProcessMemory(procHandle, (PVOID)((parameters*)loaderDest + 1), loadDll, 0x1000 - sizeof(parameters), &nBytesWritten);

	cout << "[+] written loader to " << hex << (DWORD)((parameters*)loaderDest + 1) << "." << endl;

	//--------------------------------run the loader -------------------------------------------

	HANDLE threadH = CreateRemoteThread(procHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)((parameters*)loaderDest + 1), loaderDest, NULL, NULL);

	if (!threadH)
	{
		cout << "[ERROR] starting the loader inside the target." << endl;
		delete[] dosHead;
		VirtualFreeEx(procHandle, (LPVOID)realBase, NULL, MEM_RELEASE);
		CloseHandle(procHandle);
		return 0;
	}

	WaitForSingleObject(threadH, INFINITE);

	VirtualFreeEx(procHandle, loaderDest, 0, MEM_RELEASE);

	return 0;
}