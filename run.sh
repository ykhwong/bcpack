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
MAIN_TOOL="./tool/main.pl"
RETCODE=0
PERL_ENABLED=0
TMP_IFS=$IFS

# Check PATH
if [ ! -z "$PATH" ]; then
	IFS=:
	for sth in $PATH
	do
		if [ -x "$sth/perl" ]; then
			PERL_ENABLED=1
		fi
	done
	IFS=$TMP_IFS
fi

# Check perl availability
if [ $PERL_ENABLED -eq 0 ]; then
	echo "Perl is not available."
	read tmp
	exit 1
fi

# Set LANG to C
export LANG=C

# Check main tool
if [ ! -f ${MAIN_TOOL} ]; then
	echo "File not found: ${MAIN_TOOL}"
	read tmp
	exit 1
fi

# Execute the main tool
perl "$MAIN_TOOL" $@
RETCODE=$?
if [ $RETCODE -ne 0 ]; then
	exit $RETCODE
fi
