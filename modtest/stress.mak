.SUFFIXES:
.SUFFIXES: .rc .h .c .o .cpp

CPP  = cl.exe
RSC  = rc.exe
LINK = link.exe
LIB  = lib.exe
RSC  = rc.exe

LDFLAGS = /nologo /subsystem:console /pdb:none /machine:I386 \
          /libpath:"\devstudio\vc98\lib" /nodefaultlib:libc
DEFINES= /D WIN32 /D NDEBUG /D _WINDOWS /D _MBCS
CFLAGS = /nologo /MD /W3 /GX /O2 /c
INCS = /I "." /I "\devstudio\vc98\include" /I "\oracle\include\oci"

WINLIBS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib \
          advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib \
          odbc32.lib odbccp32.lib  kernel32.lib user32.lib gdi32.lib \
          winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib \
          oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib

OBJS    = stress.obj

all:  stress.exe

stress.exe: $(OBJS)
	$(LINK) $(LDFLAGS) /out:$@ $(OBJS) $(WINLIBS)

.c.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.cpp.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.cxx.obj:
   $(CPP) $(CFLAGS) $(DEFINES) $(INCS) $<

.rc.res:
   $(RSC) $<
