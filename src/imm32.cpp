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

#if _WIN64
#else

#if ADDITIONAL_COMP
MAKE_FUNC_READY(ImmDisableTextFrameService, IsXpOrHigher_2K, "IMM32.DLL", BOOL, DWORD idThread)
MAKE_FUNC_BEGIN(ImmDisableTextFrameService, idThread) {
	// FIX ME
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(ImmEnumInputContext, IsXpOrHigher_2K, "IMM32.DLL", BOOL, DWORD idThread, IMCENUMPROC lpfn, LPARAM lParam)
MAKE_FUNC_BEGIN(ImmEnumInputContext, idThread, lpfn, lParam) {
	// FIX ME
	return FALSE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(ImmGetHotKey, IsXpOrHigher_2K, "IMM32.DLL", BOOL, DWORD hotkey, UINT *modifiers, UINT *key, HKL hkl)
MAKE_FUNC_BEGIN(ImmGetHotKey, hotkey, modifiers, key, hkl) {
	// FIX ME
	return FALSE;
}
MAKE_FUNC_END
#endif // ADDITIONAL_COMP

#endif // _WIN64
