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
MAKE_FUNC_READY(PathIsRootA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", BOOL, LPCSTR lpszPath)
MAKE_FUNC_BEGIN(PathIsRootA, lpszPath) {
	//TRACE("(%s)\n", debugstr_a(lpszPath));

	if (lpszPath && *lpszPath) {
		if (*lpszPath == '\\') {
			if (!lpszPath[1])
				return TRUE; /* \ */
			else if (lpszPath[1] == '\\') {
				BOOL bSeenSlash = FALSE;
				lpszPath += 2;

				/* Check for UNC root path */
				while (*lpszPath) {
					if (*lpszPath == '\\') {
						if (bSeenSlash)
							return FALSE;
						bSeenSlash = TRUE;
					}
					lpszPath = CharNextA(lpszPath);
				}
				return TRUE;
			}
		} else if (lpszPath[1] == ':' && lpszPath[2] == '\\' && lpszPath[3] == '\0')
			return TRUE; /* X:\ */
	}
	return FALSE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(PathRemoveFileSpecA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", BOOL, LPSTR lpszPath)
MAKE_FUNC_BEGIN(PathRemoveFileSpecA, lpszPath) {
	LPSTR lpszFileSpec = lpszPath;
	BOOL bModified = FALSE;

	//TRACE("(%s)\n", debugstr_a(lpszPath));

	if (lpszPath) {
		/* Skip directory or UNC path */
		if (*lpszPath == '\\')
			lpszFileSpec = ++lpszPath;
		if (*lpszPath == '\\')
			lpszFileSpec = ++lpszPath;

		while (*lpszPath) {
			if (*lpszPath == '\\')
				lpszFileSpec = lpszPath; /* Skip dir */
			else if (*lpszPath == ':') {
				lpszFileSpec = ++lpszPath; /* Skip drive */
				if (*lpszPath == '\\')
					lpszFileSpec++;
			}
			if (!(lpszPath = CharNextA(lpszPath)))
				break;
		}

		if (*lpszFileSpec) {
			*lpszFileSpec = '\0';
			bModified = TRUE;
		}
	}
	return bModified;
}
MAKE_FUNC_END


MAKE_FUNC_READY(PathStripToRootA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", BOOL, LPSTR lpszPath)
MAKE_FUNC_BEGIN(PathStripToRootA, lpszPath) {
	//TRACE("(%s)\n", debugstr_a(lpszPath));

	if (!lpszPath)
		return FALSE;
	while (!_PathIsRootA(lpszPath))
		if (!_PathRemoveFileSpecA(lpszPath))
			return FALSE;
	return TRUE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(PathIsUNCA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", BOOL, LPCSTR lpszPath)
MAKE_FUNC_BEGIN(PathIsUNCA, lpszPath) {
	//TRACE("(%s)\n",debugstr_a(lpszPath));
	if (lpszPath && (lpszPath[0] == '\\') && (lpszPath[1] == '\\'))
		return TRUE;
	return FALSE;
}
MAKE_FUNC_END


MAKE_FUNC_READY(PathFindFileNameA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", LPSTR, LPCSTR lpszPath)
MAKE_FUNC_BEGIN(PathFindFileNameA, lpszPath) {
	LPCSTR lastSlash = lpszPath;

	//TRACE("(%s)\n",debugstr_a(lpszPath));

	while (lpszPath && *lpszPath) {
		if ((*lpszPath == '\\' || *lpszPath == '/' || *lpszPath == ':') &&
			lpszPath[1] && lpszPath[1] != '\\' && lpszPath[1] != '/')
			lastSlash = lpszPath + 1;
		lpszPath = CharNextA(lpszPath);
	}
	return (LPSTR)lastSlash;
}
MAKE_FUNC_END


MAKE_FUNC_READY(PathFindExtensionA, Is2kOrHigher_98MENT, "SHLWAPI.DLL", LPSTR, LPCSTR lpszPath)
MAKE_FUNC_BEGIN(PathFindExtensionA, lpszPath) {
  LPCSTR lastpoint = NULL;

  //TRACE("(%s)\n", debugstr_a(lpszPath));

  if (lpszPath) {
    while (*lpszPath) {
      if (*lpszPath == '\\' || *lpszPath==' ')
        lastpoint = NULL;
      else if (*lpszPath == '.')
        lastpoint = lpszPath;
      lpszPath = CharNextA(lpszPath);
    }
  }
  return (LPSTR)(lastpoint ? lastpoint : lpszPath);
}
MAKE_FUNC_END

#endif // ADDITIONAL_COMP

#endif // _WIN64
