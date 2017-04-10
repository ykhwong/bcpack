
BCPack v0.1 for Visual Studio
===============================
Author: Taewoong Yoo
Website: http://ykhwong.x-y.net


1. INTRODUCTION
--------------------------
C/C++ applications compiled on the latest version of Visual Studio do not
support Windows 2000 or below.
This BCPack will help you to run the applications under older operating
systems. BC stands for backward compatibility.

BCPack alone can work on Windows and Unix-like operating systems including
Linux and macOS.

For a full support, please have Visual Studio 2017 or higher installed.


2. HOW THIS WORKS
--------------------------
1) A Perl-based script is executed
   - config.cfg configuration file is loaded
   - A new workspace is created
   - BCPACK.lib is compiled and created
2) The compiled library file can be added to your own project
3) Compiled application from the project can be executed on
   older versions of Windows


3. REQUIREMENTS
--------------------------
1) Perl 5
   For Windows, install Perl such as Strawberry Perl.
   (Download from http://strawberryperl.com/)
   For Unix-like operating system, the Perl software is usually installed
   by default. If not, type the following command:
   [CentOS/RHEL]
     $ yum -y install perl
   [Ubuntu]
     $ sudo apt-get install perl

2) MSBuild or the latest version of Visual Studio
   - For Unix-like, only creating a workspace is supported as of April, 2017.
     To build a library, please use Microsoft Windows.
   - For Windows, please install Visual Studio 2017 or higher.


4. WORKSPACE PREPARATION
--------------------------
WINDOWS
1) Extract the BCPack archive.
2) Open config.cfg and check the information.
   (Please refer to the CONFIG FILE section for details)
3) Run run.bat to create workspace and BCPACK.lib.
   To create workspace directory only,
   please type "run.bat --do-not-compile"
4) To clean up the workspace, please run "clean.bat"

UNIX-LIKE
1) Extract the BCPack archive.
2) Open config.cfg and check the information.
   (Please refer to the CONFIG FILE section for details)
3) Unix-like operating systems currently do not compile the
   BCPACK library file.
   To create workspace directory only,
   please type "sh run.sh --do-not-compile"
4) To clean up the workspace, please run "sh clean.sh"


5. HOW TO USE IN THE APP
--------------------------
1) After the BCPACK.lib is successfully compiled from above,
   open your own project file.
2) In Solution Explorer, select the project.
   On the Project menu, click Properties.
3) Click C/C++ and Select Code Generation -> Runtime Library.
   Select Multi-threaded (/MT).
4) Add the BCPACK.lib to the project (Linker->Input->Additional dependency)
   via Property page.
5) Select the Build Events tab. In the Post-build event command line box,
   type the following:
   copy "$(TargetPath)" "$(TargetPath).bak" >nul
   editbin.exe "$(TargetPath)" /SUBSYSTEM:CONSOLE,4.0 /OSVERSION:4.0
6) Compile your own project.
7) Copy the compiled executable to older version of Windows and run it.


6. CONFIG FILE
--------------------------
config.cfg is the configuration file that you can freely modify
before creating the library file.

COMMON SECTION
common section contains useful options for the compatibility details.

 [common]
 MSBUILD_PATH={MSBuild path}
 MSBUILD_OPT={MSBuild options}
 WORKSPACE_PATH={Workspace path}
 WIN2K_COMP={0|1}                Set to 1 to ensure Windows 2000 compatibility
 WIN98_COMP={0|1}                Set to 1 to ensure Windows 98 compatibility
 WIN95_COMP={0|1}                Set to 1 to ensure Windows 95 compatibility
 DEBUG_COMP={0|1}                Set to 1 when compiling your application
                                 with debug mode
 ADDITIONAL_COMP={0|1}           Set to 1 for better compatibility
 FORCED_FUNC={0|1}               Set to 1 if the internally implemented
                                 functions must be used regardless of
                                 operating system
 FORCED_DUMMY={0|1}              Makes every functions dummy

OTHER SECTIONS
 [win2k_func]      : Necessary functions for Windows 2000
 [win98_func]      : Necessary functions for Windows 98
 [win95_func]      : Necessary functions for Windows 95
 [debug_func]      : Necessary functions when compiling with debug mode
 [additional_func] : Additional functions

Above sections have the following structure:
    Function             : Function name
	No._of_arguments * 4 : How many arguments will be used for the function
	Opearing system      : win95, win98, win2k, and default
	DLL filename         : BCPACK filename corresponding to the system BCPACK
	=(1/0)               : 1=Enabled, 0=Disabled

For example, below line
    EncodePointer,4,win2k,kernel32=1
will support EncodePointer function with a single argument +
										 win2k compatibility +
										 kernel32



7. CHANGELOG
--------------------------
v0.1 - Apr. 10. 2017
       Initial release
       Only provides Win2k compatibility


8. TO-DO
-----------------
Better support for Windows 95, 98, and ME


9. TROUBLESHOOTING
--------------------------
OllyDbg http://www.ollydbg.de/
Dependency Walker http://www.dependencywalker.com/
API Monitor http://www.rohitab.com/apimonitor/


10. SEE ALSO
--------------------------
MSBuild engine is now open source on GitHub.
https://github.com/Microsoft/msbuild


11. CREDITS
--------------------------
ReactOS, Wine, and Windows 2000 XP API Wrapper Pack

