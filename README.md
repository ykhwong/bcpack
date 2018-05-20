# BCPack v0.1 for Visual Studio
- Author: Taewoong Yoo
- Website: http://ykhwong.x-y.net

## INTRODUCTION
C/C++-based applications compiled on the latest version of Visual Studio do not support Windows 2000 or below. This BCPack will let you build applications compatible with the old operating systems. BC stands for backward compatibility.

BCPack alone can work on Windows and Unix-like operating systems including Linux and macOS. However, for a complete support, please have Visual Studio 2017 or higher installed on Windows 10.

## Getting started
### Prerequisites
**1. Perl 5**
* **Windows**

Just install Perl such as Strawberry Perl. (Download from http://strawberryperl.com/)

* **Unix-like operating system**

Type the following command for the manual installation:
```sh
$ yum -y install perl # CentOS/RHEL
```
```sh
$ sudo apt-get install perl # Ubuntu
```

**2. Visual Studio 2017**
- Any edition of Visual Studio 2017 is supported on Windows.
- Without the VS2017, only creating a workspace is supported under Unix-like operating systems.

### Downloading BCPack
Clone BCPack onto your local machine.
```sh
$ git clone https://github.com/ykhwong/bcpack.git
```

## Building BCPack library with a workspace
1. Open the config.cfg and check the information. (Please refer to the CONFIG FILE section, especially)

2. On Windows, please run *run.bat* to create workspace and BCPACK.lib.
```
run.bat
```
Check whether the BCPack.lib is compiled successfully in the current working path. Please add <code>--show-config</code> to show the configuration details at startup.

3. On Unix-like operating system, you cannot compile the library. To create workspace directory only, please type:
```
sh run.sh --do-not-compile
```
4. To clean up the workspace, run <code>clean.bat</code> on Windows. On Linux, run <code>sh clean.sh</code>.

## Building your own application with the BCPack library
1. Please make sure that the BCPACK.lib has been succesfully built from the above step.
2. Open your own project file with Visual Studio 2017.
3. In Solution Explorer, select the project. On the Project menu, click Properties.
4. Click C/C++ and Select Code Generation -> Runtime Library. Select Multi-threaded (/MT).
5. Add the BCPACK.lib to the project (Linker->Input->Additional dependency) via Property page. (e.g, BCPACK.lib;kernel32.lib;user32.lib;...)
6. Go to the Linker->General->Force File Output and enable /FORCE:MULTIPLE.
7. Select the Build Events tab. In the Post-build event command line box, type the following:
```
copy "$(TargetPath)" "$(TargetPath).bak" >nul
editbin.exe "$(TargetPath)" /SUBSYSTEM:CONSOLE,4.0 /OSVERSION:4.0
```
8. Compile your own project.
9. Copy the compiled executable to older version of Windows and run it.

## Config file
config.cfg is the configuration file that you can freely modify before creating the library file.

**COMMON SECTION**

common section contains useful options for the compatibility details.
```
 [common]
 MSBUILD_PATH={MSBuild path}
 MSBUILD_OPT={MSBuild options}
 WORKSPACE_PATH={Workspace path}
 DEBUG_LOGLVL={0|1}              Set to 1 to enable the runtime debugging
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
```

***OTHER SECTIONS***

```
 [win2k_func]      : Necessary functions for Windows 2000
 [win98_func]      : Necessary functions for Windows 98
 [win95_func]      : Necessary functions for Windows 95
 [debug_func]      : Necessary functions when compiling with debug mode
 [additional_func] : Additional functions
```

Above sections have the following structure:
* Function             : Function name
* No._of_arguments * 4 : How many arguments will be used for the function
* Opearing system      : win95, win98, win2k, and default
* DLL filename         : BCPACK filename corresponding to the system BCPACK
* =(1/0)               : 1=Enabled, 0=Disabled

For example, <code>EncodePointer,4,win2k,kernel32=1</code> provides a support for the EncodePointer function with a single argument with win2k compatibility in the kernel32.


## Changelog
* v0.1 - Apr. 10. 2017
Initial release
Only provides Win2k compatibility

## TO-DO
* Better support for Windows 95, 98, and ME

## Troubleshooting
* OllyDbg http://www.ollydbg.de/
* Dependency Walker http://www.dependencywalker.com/
* API Monitor http://www.rohitab.com/apimonitor/

## See also
* MSBuild engine is now open source on GitHub. (https://github.com/Microsoft/msbuild)

## Credits
* ReactOS, Wine, and Windows 2000 XP API Wrapper Pack

