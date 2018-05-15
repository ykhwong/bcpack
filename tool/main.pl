#!/bin/perl
#
# Copyright (C) 2017 Taewoong Yoo
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

use strict;
use File::Basename;
use File::Copy;

my $default_cfg = "config.cfg";
my $default_workspace_dir = "./workspace";
my $workspace_dir = $default_workspace_dir;
my $src_dir = "./src";
my $os_name = $^O;
my $do_not_compile=0;
my $msbuild_filename=0;

my ($msbuild_path, $msbuild_opt, $workspace_path, $win2k_comp, $win98_comp, $win95_comp, $debug_comp, $additional_comp, $forced_func, $forced_dummy) = (0) x 10;

my @def = ("util.h", "custom_winternl.h", "main.cpp", "targetver.h", "stdafx.cpp", "stdafx.h");
my (@win2k_func, @win98_func, @win95_func, @debug_func, @additional_func);
my @ref_files; # such as kernel32.cpp
my @enum_funcs;


package file;

sub cp_file {
	my ( $from, $to ) = @_;
	::copy( $from, $to ) or die(0);
}

sub load_file {
	my $filename = shift;
	unless ( -f $filename ) {
		print STDERR "File not found: $filename\n";
		exit 1;
	}
	open my $in, '<', $filename or die("Check the file: $filename\n");
	local $/;
	my $contents = <$in>;
	close($in);
	return $contents;
}

sub save_file {
	my ($lst, $list) = @_;
	open my $fd, ">", $lst or die(0);
	print $fd $list;
	close $fd;
	if ( ! -f $lst ) {
		print STDERR "Could not save: $lst\n";
		exit 1;
	}
}


package base;

sub create_config {
	file::save_file($default_cfg, file::load_file("./tool/config.cfg.template"));
}

sub conv_path {
	my $var = shift;
	$var =~ s/\\/\//g;
	return $var;
}


sub uniq_helper {
	my %seen;
	grep !$seen{$_}++, @_;
}

sub show_status {
	my $cnt=0;
	my $status = "MSBUILD_PATH=$msbuild_path\n" .
	"MSBUILD_OPT=$msbuild_opt\n" .
	"WORKSPACE_PATH=$workspace_path\n" .
	"WIN2K_COMP=$win2k_comp\n" .
	"WIN98_COMP=$win98_comp\n" .
	"WIN95_COMP=$win95_comp\n" .
	"DEBUG_COMP=$debug_comp\n" .
	"ADDITIONAL_COMP=$additional_comp\n" .
	"FORCED_FUNC=$forced_func\n" .
	"FORCED_DUMMY=$forced_dummy\n";

	foreach my $ls (@win2k_func) {
		$cnt++;
		$status .= "WIN2K_FUNC($cnt)=$ls\n";
	}
	$cnt=0;
	foreach my $ls (@win98_func) {
		$cnt++;
		$status .= "WIN98_FUNC($cnt)=$ls\n";
	}
	$cnt=0;
	foreach my $ls (@win95_func) {
		$cnt++;
		$status .= "WIN95_FUNC($cnt)=$ls\n";
	}
	$cnt=0;
	foreach my $ls (@debug_func) {
		$cnt++;
		$status .= "DEBUG_FUNC($cnt)=$ls\n";
	}
	$cnt=0;
	foreach my $ls (@additional_func) {
		$cnt++;
		$status .= "ADDITIONAL_FUNC($cnt)=$ls\n";
	}
	$cnt=0;
	$status .= "FILES:";
	foreach my $ls (@ref_files) {
		$cnt++;
		$status .= "$ls.cpp";
		if ($cnt ne scalar @ref_files) {
			$status .= ",";
		}
	}
	$status .= "\n";
	print $status;
}

sub create_config_for_msvc {
	my $ret = "\n";
	$ret = "_WIN_64 = OPATTR rax\n\n" .
	"WIN2K_COMP EQU $win2k_comp\n\n" .
	"WIN98_COMP EQU $win98_comp\n\n" .
	"WIN95_COMP EQU $win95_comp\n\n" .
	"DEBUG_COMP EQU $debug_comp\n\n" .
	"ADDITIONAL_COMP EQU $additional_comp\n";
	file::save_file ("$workspace_dir/config.inc", $ret);
	
	$ret = "/* Minimum Windows 2000 compatibility */\n" .
	"#define WIN2K_COMP $win2k_comp\n\n" .
	"/* Minimum Windows 98 compatibility */\n" .
	"#define WIN98_COMP $win98_comp\n\n" .
	"/* Minimum Windows 95 compatibility */\n" .
	"#define WIN95_COMP $win95_comp\n\n" .
	"/* Debug compatibility */\n" .
	"#define DEBUG_COMP $debug_comp\n\n" .
	"/* Additional components for better compatibility */\n" .
	"#define ADDITIONAL_COMP $additional_comp\n\n" .
	"/* Force all functions regardless of operating system */\n" .
	"#define FORCED_FUNC $forced_func\n\n" .
	"/* Make all dummy */\n" .
	"#define FORCED_DUMMY $forced_dummy\n";
	file::save_file ("$workspace_dir/config.h", $ret);
}

sub populate_asm_func1 {
	# Adds asm functions
	my @func = @_;
	my $ret;
	foreach my $ls (@func) {
		my ($func_name, $num_arg, $os, $file) = split /,/, $ls;
		my $cnt_arg = $num_arg / 4;
		$ret .= ' _' . $func_name . ' PROTO STDCALL';
		if ($num_arg == 0) {
			$ret .= "\n";
			next;
		}
		$ret .= " ";
		foreach (1 .. $cnt_arg) {
			$ret .= ":DWORD, ";
		}
		$ret =~ s/, $//;
		$ret .= "\n";
	}
	return $ret;
}

sub populate_asm_func2 {
	# Adds __imp__
	my @func = @_;
	my $ret;
	foreach my $ls (@func) {
		my ($func_name, $num_arg, undef, undef) = split /,/, $ls;
		$ret .= ' __imp__' . $func_name . '@' . $num_arg . ' dd _' . $func_name . "\n";
	}
	return $ret;
}

sub populate_asm_func3 {
	# Adds EXTERNDEF
	my @func = @_;
	my $ret;
	foreach my $ls (@func) {
		my ($func_name, $num_arg, undef, undef) = split /,/, $ls;
		$ret .= ' EXTERNDEF __imp__' . $func_name . '@' . $num_arg . " : DWORD\n";
	}
	return $ret;
}

sub populate_asm_func {
	my $opt = shift;
	my $ret;
	if (@win2k_func) {
		if ($opt eq 1) {
			$ret .= populate_asm_func1(@win2k_func);
		} elsif ($opt eq 2) {
			$ret .= populate_asm_func2(@win2k_func);
		} elsif ($opt eq 3) {
			$ret .= populate_asm_func3(@win2k_func);
		}
		$ret .= "\n";
	}
	if (@win98_func) {
		$ret .= "IF WIN98_COMP\n";
		if ($opt eq 1) {
			$ret .= populate_asm_func1(@win98_func);
		} elsif ($opt eq 2) {
			$ret .= populate_asm_func2(@win98_func);
		} elsif ($opt eq 3) {
			$ret .= populate_asm_func3(@win98_func);
		}
		$ret .= "ENDIF\n\n";
	}
	if (@win95_func) {
		$ret .= "IF WIN95_COMP\n";
		if ($opt eq 1) {
			$ret .= populate_asm_func1(@win95_func);
		} elsif ($opt eq 2) {
			$ret .= populate_asm_func2(@win95_func);
		} elsif ($opt eq 3) {
			$ret .= populate_asm_func3(@win95_func);
		}
		$ret .= "ENDIF\n\n";
	}
	if (@debug_func) {
		$ret .= "IF DEBUG_COMP\n";
		if ($opt eq 1) {
			$ret .= populate_asm_func1(@debug_func);
		} elsif ($opt eq 2) {
			$ret .= populate_asm_func2(@debug_func);
		} elsif ($opt eq 3) {
			$ret .= populate_asm_func3(@debug_func);
		}
		$ret .= "ENDIF\n\n";
	}
	if (@additional_func) {
		$ret .= "IF ADDITIONAL_COMP\n";
		if ($opt eq 1) {
			$ret .= populate_asm_func1(@additional_func);
		} elsif ($opt eq 2) {
			$ret .= populate_asm_func2(@additional_func);
		} elsif ($opt eq 3) {
			$ret .= populate_asm_func3(@additional_func);
		}
		$ret .= "ENDIF\n\n";
	}
	return $ret;
}

sub create_asm_for_msvc {
	my $ret;
	$ret =<<"END";

include config.inc

IF _WIN_64
ELSE

.model flat, C
END

	$ret .= populate_asm_func(1);
	$ret .= ";" x 80 . "\n\n.data\n\n";
	$ret .= populate_asm_func(2);
	$ret .= ";" x 80 . "\n\n";
	$ret .= populate_asm_func(3);
	$ret .= "\n\n.code\n\nENDIF\n\nend\n";
	file::save_file("$workspace_dir/compt.asm", $ret);
}

sub replace_os_in_cpp {
	my ($ls, $os) = @_;
	if ($os eq "default") {
		# uses default
	} elsif ($os eq "win2k") {
		$ls =~ s/(IsXpOrHigher_2K|Is2kOrHigher_98MENT|Is98OrHigher_95)/IsXpOrHigher_2K/;
	} elsif ($os eq "win98") {
		$ls =~ s/(IsXpOrHigher_2K|Is2kOrHigher_98MENT|Is98OrHigher_95)/Is2kOrHigher_98MENT/;
	} elsif ($os eq "win95") {
		$ls =~ s/(IsXpOrHigher_2K|Is2kOrHigher_98MENT|Is98OrHigher_95)/Is98OrHigher_95/;
	}
	return $ls;
}

sub save_enum_helper {
	my $content = shift;
	my $result;
	my $cnt=0;
	foreach my $ls (split /\n/, $content) {
		if ($ls =~ /^\s*(static|const) (.+)$/) {
			my $data = $2;
			my $data2;
			if ($data !~ /\(/) { next; }
			$data2 = (split /\(/, $data)[0];
			if ($data2 =~ / (\S+)$/) {
				$data2 = $1;
				$data2 =~ s/^\*//;
				push @enum_funcs, $data2;
			}
		}
	}
	@enum_funcs = uniq_helper(@enum_funcs);
	foreach my $func (@enum_funcs) {
		$cnt++;
		$result .= "#define $func _A" . $cnt . "\n";
	}
	$result .=
	"#define IsXpOrHigher_2K _B1\n" .
	"#define Is2kOrHigher_98MENT _B2\n" .
	"#define Is98OrHigher_95 _B3\n";
	file::save_file("$workspace_dir/enum.h", $result);
}

sub save_enum {
	save_enum_helper(file::load_file("$src_dir/util.h"));
	foreach my $file (@ref_files) {
		save_enum_helper(file::load_file("$workspace_dir/$file" . ".cpp"));
		if ( -f "$workspace_dir/$file.h" ) {
			save_enum_helper(file::load_file("$workspace_dir/$file" . ".h"));
		}
	}
}

sub load_and_copy_cpp_files {
	#create common.h
	my ($content, $result);
	foreach my $file (@def) {
		file::cp_file("$src_dir/$file", "$workspace_dir/$file");
	}
	foreach my $file (@ref_files) {
		if ( -f "$src_dir/$file" . ".h" ) {
			file::cp_file("$src_dir/$file" . ".h", "$workspace_dir/$file" . ".h");
		}
		$content = file::load_file("$src_dir/$file" . ".cpp");
		foreach my $ls (split /\n/, $content) {
			if ($ls =~ /^\s*MAKE_FUNC_READY\s*\((.+)$/) {
				my $tmp_ls = $1;
				$tmp_ls =~ s/\)\s*$//;
				my @chunk = split /,\s*/, $tmp_ls;
				my ($cpp_func_name, $cpp_os) = ($chunk[0], $chunk[1]);
				my $cpp_num_arg = scalar @chunk;
				$cpp_num_arg -= 4;
				$cpp_num_arg *= 4;

				foreach my $item (@win2k_func) {
					my ($func_name, $num_arg, $os, undef) = split /,/, $item;
					if ($num_arg eq $cpp_num_arg && $func_name eq $cpp_func_name) {
						$ls = replace_os_in_cpp($ls, $os);
						last;
					}
				}
				foreach my $item (@win98_func) {
					my ($func_name, $num_arg, $os, undef) = split /,/, $item;
					if ($num_arg eq $cpp_num_arg && $func_name eq $cpp_func_name) {
						$ls = replace_os_in_cpp($ls, $os);
						last;
					}
				}
				foreach my $item (@win95_func) {
					my ($func_name, $num_arg, $os, undef) = split /,/, $item;
					if ($num_arg eq $cpp_num_arg && $func_name eq $cpp_func_name) {
						$ls = replace_os_in_cpp($ls, $os);
						last;
					}
				}
				foreach my $item (@debug_func) {
					my ($func_name, $num_arg, $os, undef) = split /,/, $item;
					if ($num_arg eq $cpp_num_arg && $func_name eq $cpp_func_name) {
						$ls = replace_os_in_cpp($ls, $os);
						last;
					}
				}
				foreach my $item (@additional_func) {
					my ($func_name, $num_arg, $os, undef) = split /,/, $item;
					if ($num_arg eq $cpp_num_arg && $func_name eq $cpp_func_name) {
						$ls = replace_os_in_cpp($ls, $os);
						last;
					}
				}
			}
			$result .= $ls . "\n";
		}
		file::save_file("$workspace_dir/$file" . ".cpp", $result);
		undef $result;
	}
}

sub create_common_header_for_msvc {
	my ($ret, $content, @cols);
	$ret = file::load_file("./tool/common.h.template");
	foreach my $file (@ref_files) {
		$content = file::load_file("$workspace_dir/$file" . ".cpp");
		foreach my $ls (split /\n/, $content) {
			if ($ls =~ /^\s*MAKE_FUNC_READY\s*\(/) {
				$ls =~ s/^\s*MAKE_FUNC_READY\s*\(/EXTERN_FUNC(/;
				#print "$workspace_dir/$file : $ls\n";
				push @cols, $ls;
			}
		}
	}
	@cols = uniq_helper(@cols);
	foreach my $ls (@cols) {
		$ret .= $ls . "\n";
	}
	file::save_file("$workspace_dir/common.h", $ret);
}

sub check_dir {
	my @dirs = ($src_dir, $workspace_dir);
	if ( ! -d $src_dir ) {
		print "ERROR: Directory not found: $src_dir\n";
		exit 1;
	}
	if ( ! -d $workspace_dir ) {
		mkdir($workspace_dir);
		if ( ! -d $workspace_dir ) {
			print "ERROR: Directory not found: $workspace_dir\n";
			exit 1;
		}
	}
	foreach my $ls (@ref_files) {
		if ( ! -f "$src_dir/$ls.cpp" ) {
			print "ERROR: File not found: $src_dir/$ls.cpp\n";
			exit 1;
		}
	}
}

sub check_comma_struc {
	my ($str, $status) = @_;
	my $num = scalar (split ',', $str);
	unless ($num == 4) {
		print STDERR "Invalid structure in [$status]: $str\n";
		exit 1;
	}
}

sub check_msbuild_status {
	my $retcode;
	if ($do_not_compile eq 1) {
		return;
	}
	if ( !$msbuild_path ) {
		print STDERR "MSBUILD_PATH is not set\n";
		exit 1;
	}
	if ( !$msbuild_opt ) {
		print STDERR "MSBUILD_OPT is not set\n";
		exit 1;
	}
	if ( ! -f "$msbuild_path/$msbuild_filename" ) {
		print STDERR "ERROR - msbuild not available: $msbuild_path/$msbuild_filename\n";
		exit 1;
	}
	`"$msbuild_path/$msbuild_filename" /?`;
	$retcode = $?;
	if ($retcode != 0) {
		print STDERR "ERROR($retcode) - msbuild not available: $msbuild_path/$msbuild_filename\n";
		exit 1;
	}
}

sub register_config {
	if ( ! -f $default_cfg ) {
		print "Creating a configuration file ($default_cfg)...\n";
		create_config();
	}
	if ( ! -f $default_cfg ) {
		print STDERR "ERROR - no permission to create $default_cfg\n";
		exit 1;
	}
	my $contents = file::load_file($default_cfg);
	my $status=0;
	foreach my $ls (split /\n/, $contents) {
		if ($ls =~ /^\s*$/ || $ls =~ /^\s*\Q#\E/) {
			next;
		}
		if ($ls =~ /^\s*\[(\S+)\]/) {
			$status=$1;
			next;
		}
		if ($status =~ /^common$/) {
			if ($ls =~ /^\s*MSBUILD_PATH=(.+)$/) {
				$msbuild_path=$1;
				$msbuild_path =~ s/(\r|\n)//g;
				$msbuild_path = conv_path($msbuild_path);
				next;
			}
			if ($ls =~ /^\s*MSBUILD_OPT=(.+)$/) {
				$msbuild_opt=$1; $msbuild_opt =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*WORKSPACE_PATH=(.+)$/) {
				$workspace_path=$1; $workspace_path =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*WIN2K_COMP=(.+)$/) {
				$win2k_comp=$1; $win2k_comp =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*WIN98_COMP=(.+)$/) {
				$win98_comp=$1; $win98_comp =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*WIN95_COMP=(.+)$/) {
				$win95_comp=$1; $win95_comp =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*DEBUG_COMP=(.+)$/) {
				$debug_comp=$1; $debug_comp =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*ADDITIONAL_COMP=(.+)$/) {
				$additional_comp=$1; $additional_comp =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*FORCED_FUNC=(.+)$/) {
				$forced_func=$1; $forced_func =~ s/(\r|\n)//g; next;
			}
			if ($ls =~ /^\s*FORCED_DUMMY=(.+)$/) {
				$forced_dummy=$1; $forced_dummy =~ s/(\r|\n)//g; next;
			}
		}
		if ($status =~ /^win2k_func$/) {
			if ($ls =~ /=1\s*$/) {
				$ls =~ s/=1\s*$//;
				check_comma_struc($ls, $status);
				push @win2k_func, $ls;
				push @ref_files, (split /,/, $ls)[3];
				next;
			}
		}
		if ($status =~ /^win98_func$/) {
			if ($ls =~ /=1\s*$/) {
				$ls =~ s/=1\s*$//;
				check_comma_struc($ls, $status);
				push @win98_func, $ls;
				push @ref_files, (split /,/, $ls)[3];
				next;
			}
		}
		if ($status =~ /^win95_func$/) {
			if ($ls =~ /=1\s*$/) {
				$ls =~ s/=1\s*$//;
				check_comma_struc($ls, $status);
				push @win95_func, $ls;
				push @ref_files, (split /,/, $ls)[3];
				next;
			}
		}
		if ($status =~ /^debug_func$/) {
			if ($ls =~ /=1\s*$/) {
				$ls =~ s/=1\s*$//;
				check_comma_struc($ls, $status);
				push @debug_func, $ls;
				push @ref_files, (split /,/, $ls)[3];
				next;
			}
		}
		if ($status =~ /^additional_func$/) {
			if ($ls =~ /=1\s*$/) {
				$ls =~ s/=1\s*$//;
				check_comma_struc($ls, $status);
				push @additional_func, $ls;
				push @ref_files, (split /,/, $ls)[3];
				next;
			}
		}
	}
	@ref_files = base::uniq_helper(@ref_files);
}

sub compile {
	my $content = file::load_file("./tool/BCPACK.vcxproj.template");
	my $result;
	foreach my $ls (split /\n/, $content) {
		if ($ls =~ /\Q<ClCompile Include="..\workspace\main.cpp" \E/) {
			$result .= $ls . "\n";
			foreach my $file (@ref_files) {
				$result .= '    <ClCompile Include="..\\' . $workspace_dir . "\\" . $file . ".cpp" . '" />' . "\n";
			}
			next;
		}
		$result .= $ls . "\n";
	}
	$result =~ s/\Q"..\workspace\\E/"..\\$workspace_dir/mg;
	if ($os_name eq 'MSWin32') {
		my $pf_path = $ENV{'ProgramFiles(x86)'};
		my $final_pf;
		if ($pf_path =~ /\S/) {
			$pf_path = $pf_path . "/Windows Kits/10/bin";
			if ( -d $pf_path ) {
				opendir( my $DIR, $pf_path );
				my @pf_files = sort { $a <=> $b } readdir($DIR);
				while ( my $entry = shift @pf_files ) {
					next unless -d $pf_path . '/' . $entry;
					next if $entry eq '.' or $entry eq '..';
					next if $entry !~ /^\d(.+)\d$/;
					$final_pf = $entry;
				}
				closedir $DIR;
				$result =~ s/<WindowsTargetPlatformVersion>(.+)<\/WindowsTargetPlatformVersion>/<WindowsTargetPlatformVersion>$final_pf<\/WindowsTargetPlatformVersion>/;
			}
		}
	}
	file::save_file("$workspace_dir/BCPACK.vcxproj", $result);
	print "Workspace created: $workspace_dir\n";
	if ($do_not_compile eq 1) {
		return;
	}
	print "Waiting for the compilation...\n";
	my $cmd = '"' . "$msbuild_path/$msbuild_filename" . '" ';
	$cmd .= "/p:OutDir=..\\ $msbuild_opt /clp:ErrorsOnly " . '"' . "$workspace_dir/BCPACK.vcxproj" . '"';
	print "[CMD] " . $cmd . "\n\n";
	my $cmd_out = `$cmd`;
	print $cmd_out . "\n";
	print "Done.\n";
}

sub init {
	if (@ARGV) {
		foreach my $arg (@ARGV) {
			if ($arg =~ /^--(help|h)/) {
				print "USAGE: $0 [--do-not-compile]\n";
				exit 0;
			}
			if ($arg =~ /^--(do-not-compile)/) {
				$do_not_compile=1;
			}
		}
	}
	if ($os_name eq 'MSWin32') {
		$msbuild_filename="msbuild.exe";
	} else {
		$msbuild_filename="msbuild";
	}
}

sub main {
	init();
	register_config();
	check_dir();
	#show_status();
	create_config_for_msvc();
	check_msbuild_status();
	create_asm_for_msvc();

	load_and_copy_cpp_files();
	create_common_header_for_msvc();
	save_enum();
	compile();
}

base::main();
