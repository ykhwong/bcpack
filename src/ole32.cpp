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
MAKE_FUNC_READY(CoInitializeEx, Is2kOrHigher_98MENT, "OLE32.DLL", HRESULT, _In_opt_ LPVOID pvReserved, _In_     DWORD  dwCoInit)
MAKE_FUNC_BEGIN(CoInitializeEx, pvReserved, dwCoInit) {
	return CoInitialize(pvReserved);
}
MAKE_FUNC_END
#endif // ADDITIONAL_COMP

#endif // _WIN64
