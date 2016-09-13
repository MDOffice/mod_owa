/*
** stress.c
**
** Build me with:    cc -o stress stress.c -lpthread -lc
** Run me with:      stress <IP address> <port number> <nthreads>
** Example:          stress 127.0.0.1 80 10
*/

/*
** Build with
*/
#ifdef TEST_PLAIN_URL
#define URL   "/index.html"
#else /* TEST MODOWA URL */
#define URL   "/owa/modowa_test_pkg.test_arguments?a=xxx&n=100"
#endif

#ifdef WIN32

#include <winsock2.h> /* winsock2.h ? */
#include <windows.h>

#else

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/fcntl.h> /* For O_CREAT, O_RDONLY, O_WRONLY, O_APPEND */
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#define MAX_THREADS  256
#define SOCK_TIMEOUT 100

#ifdef WIN32
#define os_mutex   HANDLE
#define os_socket  SOCKET
#define bad_mutex  INVALID_HANDLE_VALUE
#define bad_socket INVALID_SOCKET
#define str_length lstrlen
#define str_copy   lstrcpy
#else
#define os_mutex   int
#define os_socket  int
#define bad_mutex  -1
#define bad_socket -1
#define str_length strlen
#define str_copy   strcpy

/*
** ### HORRIBLY, POSIX LEAVES THIS DEFINITION TO YOU, AND THE
** ### COMPILER ON SOLARIS WON'T DO THE RIGHT THING WITHOUT IT.
*/
typedef union semun
{
    int   val;
    void *buf;
} owasem;

#endif

typedef struct daemon_context
{
    char     *ipaddr;
    int       port;
    int       tids[MAX_THREADS];
} daemon_context;

/*
** Print a line to standard out, followed by a line break
*/
static void std_print(char *str)
{
#ifdef WIN32
    HANDLE  fp;
    char   *send;
    char   *sptr;
    char   *aptr;
    DWORD   nbytes;
    int     slen;

    if (!str) return;

    fp = GetStdHandle(STD_OUTPUT_HANDLE);

    sptr = str;
    slen = str_length(str);
    send = sptr + slen;
    for (aptr = sptr; aptr < send; ++aptr)
    {
        if (*aptr == '\n')
        {
            nbytes = (aptr - sptr);
            if (nbytes > 0)
                if (!WriteFile(fp, sptr, nbytes, &nbytes, NULL)) break;
            sptr += nbytes;
            if (*sptr == '\n')
            {
                if (!WriteFile(fp, "\r\n", 2, &nbytes, NULL)) break;
                ++sptr;
            }
            ++slen;
        }
    }
    nbytes = (aptr - sptr);
    if (nbytes > 0) WriteFile(fp, sptr, nbytes, &nbytes, NULL);
#else
    if (str) printf("%s", str);
#endif
}

/*
** Convert string to integer
*/
static int str_atoi(char *s)
{
    int i;
    for (i = 0; (*s >= '0') && (*s <= '9'); ++s)
        i = (i * 10) + (*s - '0');
    return(i);
}

/*
** Convert integer to string
*/
int str_itoa(int i, char *s)
{
    int   j;
    int   n;
    char *sptr;
    char  buf[32];

    sptr = s;
    if (i <= 0)
    {
        j = -i;
        *(sptr++) = ((i == 0) ? '0' : '-');
    }
    else
    {
        j = i;
    }
    for (n = 0; j != 0; j = j/10) buf[n++] = '0' + (j % 10);
    for (j = n - 1; j >= 0; --j) *(sptr++) = buf[j];
    *sptr = '\0';
    return((int)(sptr - s));
}

/*
** Length-limited string comparison with case-control flag.
*/
int str_compare(const char *s1, const char *s2, int maxlen, int caseflag)
{
    int i;
    int n, m;

    if (maxlen < 0) maxlen = 0x7FFFFFF;

    if ((!s1) && (!s2)) return(0);
    if (!s1) return(-1);
    if (!s2) return(+1);
    for (i = 0; i < maxlen; ++i, ++s1, ++s2)
    {
        n = ((int)*s1 & 0xFF);
        m = ((int)*s2 & 0xFF);
        if (caseflag)
        {
            if ((n >= 'A') && (n <= 'Z')) n += ('a' - 'A');
            if ((m >= 'A') && (m <= 'Z')) m += ('a' - 'A');
        }
        n -= m;
        if (n != 0) return(n);
        if (*s1 == '\0') break;
    }
    return(0);
}

/*
** Sleep for number of milliseconds
*/
static void os_milli_sleep(int ms)
{
#ifdef WIN32
    Sleep((DWORD)ms);
#else
    poll((struct pollfd *)0, 0, ms);
#endif
}

/*
** Create a mutex
*/
static os_mutex create_mutex()
{
#ifdef WIN32
    HANDLE mh;
    mh = CreateMutex(0, FALSE, (char *)0);
    if (!mh) mh = INVALID_HANDLE_VALUE;
#else
    key_t   key;
    int     mh;
    owasem  su;

    key = IPC_PRIVATE;
    mh = semget(key, 1, IPC_CREAT | 0600);

    if (mh >= 0)
    {
        su.val = 1;
        if (semctl(mh, 0, SETVAL, su) == -1) return(-1);
    }

#endif
    return(mh);
}

/*
** Acquire mutex, timeout in milliseconds (0 = infinite)
*/
static int acquire_mutex(os_mutex mh, int timeout)
{
#ifdef WIN32
    DWORD t;
    t = (timeout < 0) ? INFINITE : timeout;
    if (WaitForSingleObject(mh, t) == WAIT_OBJECT_0) return(1);
#else
    struct sembuf sb;
    sb.sem_num = 0;
    sb.sem_op = -1;
    sb.sem_flg = SEM_UNDO;
    if (timeout >= 0)
        sb.sem_flg |= IPC_NOWAIT; /* ### TIMEOUT NOT IMPLEMENTED! ### */
    if (semop(mh, &sb, 1) == 0) return(1);
#endif
    return(0);
}

/*
** Release mutex
*/
static int release_mutex(os_mutex mh)
{
#ifdef WIN32
    if (ReleaseMutex(mh)) return(1);
#else
    struct sembuf sb;
    sb.sem_num = 0;
    sb.sem_op = 1;
    sb.sem_flg = SEM_UNDO;
    if (semop(mh, &sb, 1) == 0) return(1);
#endif
    return(0);
}

/*
** Destroy/free mutex
*/
static int destroy_mutex(os_mutex mh)
{
#ifndef WIN32
    if (semctl(mh, 0, IPC_RMID, 0) == -1) return(0);
#endif
    return(1);
}

/*
** Socket initialization
*/
static void socket_init()
{
#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2,0), &wsa_data); /* Winsock 2.0 */
#endif
}

/*
** Close a socket
*/
static void socket_close(os_socket sock)
{
#ifdef WIN32
    closesocket(sock);
#else
    close(sock); /* ### CHECK THIS ### */
#endif
}

/*
** Socket creation and binding
*/
static os_socket socket_listen(int port, char *ipaddr)
{
    os_socket          sfd;
    struct sockaddr_in saddr;

    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons((unsigned short)port);
#ifdef WIN32
    saddr.sin_addr.S_un.S_addr = inet_addr(ipaddr);
#else
#ifdef LINUX
    inet_aton(ipaddr, &saddr.sin_addr);
#else /* Solaris */
    saddr.sin_addr.s_addr = inet_addr(ipaddr);
#endif
#endif

    sfd = socket(PF_INET, SOCK_STREAM, 0);

    if (sfd != bad_socket)
    {
        if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
        {
            socket_close(sfd);
            sfd = bad_socket;
        }
        else if (listen(sfd, 5) != 0)
        {
            socket_close(sfd);
            sfd = bad_socket;
        }
    }

    return(sfd);
}

/*
** Accept a new socket connection
*/
static os_socket socket_accept(os_socket sock)
{
    os_socket          sfd;
    struct sockaddr_in saddr;
    int                n;

    n = sizeof(saddr);
#ifdef WIN32
    FillMemory((void *)&saddr, n, 0);
#else
    memset((void *)&saddr, 0, n);
#endif
    sfd = accept(sock, (struct sockaddr *)&saddr, &n);
    return(sfd);
}

/*
** Socket connect
*/
static os_socket socket_connect(int port, char *ipaddr)
{
    os_socket          sfd;
    struct sockaddr_in saddr;

    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons((unsigned short)port);
#ifdef WIN32
    saddr.sin_addr.S_un.S_addr = inet_addr(ipaddr);
#else
#ifdef LINUX
    inet_aton(ipaddr, &saddr.sin_addr);
#else /* Solaris */
    saddr.sin_addr.s_addr = inet_addr(ipaddr);
#endif
#endif

    sfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sfd != bad_socket)
    {
        if (connect(sfd, (struct sockaddr *)&saddr, sizeof(saddr)))
        {
            socket_close(sfd);
            sfd = bad_socket;
        }
    }
    return(sfd);
}

/*
** Write to a socket
*/
static int socket_write(os_socket sock, char *buffer, int buflen)
{
    int n;
#ifdef WIN32
    n = send(sock, buffer, buflen, 0);
#else
    n = write(sock, buffer, buflen);
#endif
    return(n);
}

/*
** Read from a socket
*/
static int socket_read(os_socket sock, char *buffer, int buflen)
{
    int n;
#ifdef WIN32
    n = recv(sock, buffer, buflen, 0);
#else
    n = read(sock, buffer, buflen);
#endif
    return(n);
}

/*
** Create a thread
*/
static int thread_create(void (*thread_start)(void *),
                         void *thread_context)
{
#ifdef WIN32
    HANDLE th;
    DWORD  tid;

    th = CreateThread(0,            /* security attrs */
                      (DWORD)0,     /* stack size, default is 1M */
                      (LPTHREAD_START_ROUTINE)thread_start,
                      thread_context,
                      (DWORD)0,     /* CREATE_SUSPENDED is the only value */
                      &tid);
#else
    int       status;
    int       tid;
    pthread_t th;

    status = pthread_create(&th, (pthread_attr_t *)0,
                            (void *(*)())thread_start, thread_context);
    tid = (int)th;
#endif
    return(tid);
}

/*
** Exit current thread
*/
static void thread_exit()
{
#ifdef WIN32
    ExitThread((DWORD)0);
#else
    pthread_exit((void *)0);
#endif
}

/*
** Get thread ID
*/
static int thread_getid()
{
#ifdef WIN32
    DWORD tid = GetCurrentThreadId();
#else
    int   tid = pthread_self();
#endif
    return(tid);
}

/*
** ### Test program: send and receive back simple message
*/
static void main_stress(void *data)
{
    char            buffer[8192];
    char            outline[256];
    int             n, i;
    char           *sptr;
    daemon_context *dctx = (daemon_context *)data;
    os_socket       asock;

    while (1)
    {
        asock = socket_connect(dctx->port, dctx->ipaddr);
        if (asock == bad_socket)
        {
            str_copy(outline, "Stress thread ");
            i = str_length(outline);
            i += str_itoa(thread_getid(), outline + i);
            str_copy(outline + i, " refused by Apache\n");
            std_print(outline);
        }
        else
        {
            sptr = "GET " URL " HTTP/1.0\r\n\r\n";
            n = socket_write(asock, sptr, str_length(sptr));
            n = 0;
            while (1)
            {
                i = socket_read(asock, buffer + n, sizeof(buffer)-n-1);
                if (i <= 0) break;
                n += i;
            }
            buffer[n] = 0;
            socket_close(asock);
            /* std_print(buffer); */
            str_copy(outline, "Stress thread ");
            i = str_length(outline);
            i += str_itoa(thread_getid(), outline + i);
            outline[i++] = ' ';
            str_copy(outline + i, "received ");
            i = str_length(outline);
            i += str_itoa(n, outline + i);
            str_copy(outline + i, " bytes\n");
            std_print(outline);
        }
        os_milli_sleep(100);
    }
}

int main(argc, argv)
int   argc;
char *argv[];
{
    daemon_context  dctx;
    char           *ipaddr;
    int             port;
    int             nthreads;
    int             i;

    if (argc < 4)
    {
        std_print("usage:   stress <IP address> <port number> <nthreads>\n");
        std_print("example: stress 127.0.0.1    80            10\n");
        return(0);
    }

    /*
    ** Decode the arguments
    */
    ipaddr = argv[1];
    port = str_atoi(argv[2]);
    nthreads = str_atoi(argv[3]);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > MAX_THREADS) nthreads = MAX_THREADS;

    socket_init();

    dctx.ipaddr = ipaddr;
    dctx.port = port;

    for (i = 0; i < nthreads; ++i)
        dctx.tids[i] = thread_create(main_stress, (void *)&dctx);

    while (i < MAX_THREADS) dctx.tids[i++] = -1;

    i = 0;
    while (1)
    {
        os_milli_sleep(60000); /* Once per minute */
    }

    return(0);
}
