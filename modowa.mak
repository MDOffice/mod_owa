.SUFFIXES:
.SUFFIXES: .rc .h .c .o .cpp

CPP  = cl.exe
RSC  = rc.exe
LINK = link.exe
LIB  = lib.exe
RSC  = rc.exe

ORATOP = C:\oracle\product\12.1.0\client64

APACHETOP = D:\Nick\Apache\httpd-2.4\httpd-2.4.25-win64-VC14\Apache24

VCTOP = C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC
SDKTOP = C:\Program Files (x86)\Windows Kits\8.1
CRTTOP = C:\Program Files (x86)\Windows Kits\10

# Sometimes use /debug
# Use /machine:x86 for 32-bit
LDFLAGS = /nologo /dll /pdb:none /machine:x64 /nodefaultlib:libc \
          /libpath:"$(VCTOP)\lib\amd64" /libpath:"$(SDKTOP)\Lib\winv6.3\um\x64" /libpath:"$(CRTTOP)\Lib\10.0.10240.0\ucrt\x64" \
          /libpath:$(ORATOP)\lib

# Change APACHE24 to APACHE22 or APACHE20 or EAPI
DEFINES= /D WIN64 /D NDEBUG /D _WINDOWS /D _MBCS /D _USRDLL /D APACHE24

# Use /Zi to enable debugging
CFLAGS = /nologo /MT /W3 /O2 /c

INCS = /I "." \
       /I $(APACHETOP)\include \
       /I $(APACHETOP)\src\include /I $(APACHETOP)\src\os\win32 \
       /I "$(VCTOP)\vc\include" \
       /I $(ORATOP)\oci\include

WINLIBS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib \
          advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib \
          odbc32.lib odbccp32.lib  kernel32.lib user32.lib gdi32.lib \
          winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib \
          oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib

OBJS    = owautil.obj owafile.obj owanls.obj owasql.obj owalog.obj \
          owahand.obj owaplsql.obj owadoc.obj owacache.obj modowa.obj


OCILIB = $(ORATOP)\oci\lib\msvc\oci.lib

APACHE13LIBS = $(APACHETOP)\libexec\ApacheCore.lib

APACHE20LIBS = $(APACHETOP)\lib\libhttpd.lib \
               $(APACHETOP)\lib\libapr.lib \
               $(APACHETOP)\lib\libaprutil.lib

APACHE22LIBS = $(APACHETOP)\lib\libhttpd.lib \
               $(APACHETOP)\lib\libapr-1.lib \
               $(APACHETOP)\lib\libaprutil-1.lib

APACHE24LIBS = $(APACHETOP)\lib\libhttpd.lib \
               $(APACHETOP)\lib\libapr-1.lib \
               $(APACHETOP)\lib\libaprutil-1.lib

all:  mod_owa.dll

mod_owa.dll: $(OBJS)
	$(LINK) $(LDFLAGS) /out:$@ $(OBJS) \
	$(APACHE24LIBS) $(OCILIB) $(WINLIBS)

.c.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.cpp.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.cxx.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.rc.res:
   $(RSC) $<
