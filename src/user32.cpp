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
#include "common.h"
#include "util.h"
#include "debug.h"

#if _WIN64
#else

#if ADDITIONAL_COMP
MAKE_FUNC_READY(CharLowerW, Is2kOrHigher_98MENT, "USER32.DLL", LPWSTR, LPWSTR x)
MAKE_FUNC_BEGIN(CharLowerW, x) {
	DEBUG_LOG("SHLWAPI CharLowerW: START\r\n");
	if (HIWORD(x)) {
		DEBUG_LOG("SHLWAPI CharLowerW: END (1)\r\n");
		return strlwrW(x);
	} else {
		DEBUG_LOG("SHLWAPI CharLowerW: END (2)\r\n");
		return (LPWSTR)((UINT_PTR)tolowerW(LOWORD(x)));
	}
}
MAKE_FUNC_END


MAKE_FUNC_READY(CharUpperW, Is2kOrHigher_98MENT, "USER32.DLL", LPWSTR, LPWSTR x)
MAKE_FUNC_BEGIN(CharUpperW, x) {
	DEBUG_LOG("SHLWAPI CharUpperW: START\r\n");
	if (HIWORD(x)) {
		DEBUG_LOG("SHLWAPI CharUpperW: END (1)\r\n");
		return struprW(x);
	} else {
		DEBUG_LOG("SHLWAPI CharUpperW: END (2)\r\n");
		return (LPWSTR)((UINT_PTR)toupperW(LOWORD(x)));
	}
}
MAKE_FUNC_END


MAKE_FUNC_READY(GetMenuBarInfo, Is2kOrHigher_98MENT, "USER32.DLL", BOOL, _In_ HWND hwnd, _In_ LONG idObject, _In_ LONG idItem, _Inout_ PMENUBARINFO pmb)
MAKE_FUNC_DUMMY(GetMenuBarInfo, true, hwnd, idObject, idItem, pmb)



#endif // ADDITIONAL_COMP

#endif // _WIN64
