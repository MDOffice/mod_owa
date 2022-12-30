# for build
Компиляцию запускать – nmake modowa.mak, в папке apache24
apr_perms_set.h from https://apr.apache.org/

Install the [chocolatey package manager](https://chocolatey.org/install) for Windows
Run `choco install make`

Install [C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) or [Visual Studio](https://visualstudio.microsoft.com/downloads/)
Selected "MSVS build tool", "Cmake C++ tools", "Windows 11 SDK" in component or "Desktop development with C++" in workloads
Update ./configure.bat if need

https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
D:\Apache24.39 - Binaries
D:\Apache24.39\src - Source
# mod_owa
Apache PL/SQL Gateway Module
[https://github.com/oracle/mod_owa]

## OwaValidation

#### modowa.h
to *struct owa_context* add
    before *ora_before* :
    
    char           *ora_valid;


#### modowa.c
to *static const command_rec ora_commands[]* add
    before *OwaBefore* :

	ARG_PATTERN("OwaValidation",   ARG_SET(ora_valid),  ACCESS_CONF,   TAKE1,
            "OwaValidation <valid procedure>"                          ),


#### owahand.c
to *owa_handle_request* add
   before FIRST *if (octx->ora_before)* :
 
    if (octx->ora_valid) stmtlen += (str_length(octx->ora_valid) + 23);

   before SECOND *if (octx->ora_before)* :
 
    if (octx->ora_valid)
    {
        sptr += str_concat(sptr, 0, "  if ", -1);
        sptr += str_concat(sptr, 0, octx->ora_valid, -1);
        sptr += str_concat(sptr, 0, "('", -1);
        sptr += str_concat(sptr, 0, spath, -1);
        sptr += str_concat(sptr, 0, "') = false then", -1);
        sptr += str_concat(sptr, 0,
                           (char *)((spflag == 4) ? "\n     " : "\n   "), -1);
        sptr += str_concat(sptr, 0, "return;", -1);
        sptr += str_concat(sptr, 0, "end if", -1);
        sptr += str_concat(sptr, 0,
                           (char *)((spflag == 4) ? ";\n    " : ";\n  "), -1);
    }
