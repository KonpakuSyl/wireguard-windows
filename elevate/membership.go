/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"golang.org/x/sys/windows"
)

func isAdmin(token windows.Token) bool {
	builtinAdminsGroup, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	var checkableToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityIdentification, windows.TokenImpersonation, &checkableToken)
	if err != nil {
		return false
	}
	defer checkableToken.Close()
	isAdmin, err := checkableToken.IsMember(builtinAdminsGroup)
	return isAdmin && err == nil
}

// TokenIsElevated reports whether token is an elevated administrator token.
func TokenIsElevated(token windows.Token) bool {
	return token.IsElevated() && isAdmin(token)
}

// IsElevated reports whether the current process is an elevated administrator.
func IsElevated() bool {
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return false
	}
	defer processToken.Close()
	return TokenIsElevated(processToken)
}
