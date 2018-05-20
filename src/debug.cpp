/*

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

*/

#include <windows.h>
#include <stdio.h>
#include <fstream>
#include "common.h"
#include "debug.h"

void DEBUG_LOG(char Str[]) {
#if DEBUG_LOGLVL
	/* Workaround was added because FILE_APPEND_DATA may not work for WriteFile on Win9x */
	HANDLE hLogFile_readonly;
	HANDLE hLogFile;
	char logfile[] = "bcpack_log.txt";
	char inBuffer[4096] = "\0";
	DWORD nBytesRead;

	hLogFile_readonly = CreateFileA(logfile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	bool bResult = ReadFile(hLogFile_readonly, &inBuffer, 4096, &nBytesRead, NULL) ; 
	if (bResult) {
		strcat(inBuffer, Str);
	} else {
		strcpy(inBuffer, Str);
	}
	CloseHandle(hLogFile_readonly);

	hLogFile = CreateFileA(logfile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hLogFile != INVALID_HANDLE_VALUE) {
		DWORD dwBytesWritten = 0;
		WriteFile(hLogFile, inBuffer, strlen(inBuffer), &dwBytesWritten, NULL);
	}
	CloseHandle(hLogFile);
#endif
}
