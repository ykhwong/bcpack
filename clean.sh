#!/bin/sh
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
TMP_IFS=$IFS
RM_ENABLED=0
CAT_ENABLED=0
GREP_ENABLED=0
SED_ENABLED=0
WORKSPACE_DIR=./workspace
CONFIG_FILE=config.cfg
LANG=C
PATH_VAR=$PATH:.

# Check PATH
if [ ! -z "$PATH_VAR" ]; then
	IFS=:
	for sth in $PATH_VAR
	do
		if [ -x "$sth/rm" ]; then
			RM_ENABLED=1
		fi
		if [ -x "$sth/cat" ]; then
			CAT_ENABLED=1
		fi
		if [ -x "$sth/grep" ]; then
			GREP_ENABLED=1
		fi
		if [ -x "$sth/sed" ]; then
			SED_ENABLED=1
		fi
	done
	IFS=$TMP_IFS
fi

if [ $GREP_ENABLED -eq 1 -a $CAT_ENABLED -eq 1 -a $SED_ENABLED -eq 1 ]; then
	if [ -f "$CONFIG_FILE" ]; then
		IFS='
'
		TMP_VAR=
		for sth in `cat $CONFIG_FILE`
		do
			if [ `echo $sth | grep -cP '^WORKSPACE_PATH='` -ne 0 ]; then
				TMP_VAR=`echo "$sth" | sed -e 's/\r//g' | sed 's/^WORKSPACE_PATH=//' | sed 's.\\\./.g'`
				break
			fi
		done
		IFS=$TMP_IFS
		WORKSPACE_DIR=$TMP_VAR
	fi
else
	echo "grep, sed, or cat not available. Setting WORKSPACE_DIR to $WORKSPACE_DIR"
fi

if [ -d "${WORKSPACE_DIR}" ]; then
	if [ $RM_ENABLED -eq 1 ]; then
		rm -rf ${WORKSPACE_DIR} 2>/dev/null
		if [ -d ${WORKSPACE_DIR} ]; then
			echo "Failed to remove: ${WORKSPACE_DIR}"
		else
			echo "Done"
		fi
	else
		echo "rm is not available"
		exit 1
	fi
	read tmp
else
	echo "Nothing to do"
	read tmp
fi
