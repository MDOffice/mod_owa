/*
** tunnel.c - HTTP Request interceptor/forwarder
**
** On Linux:    cc -o tunnel tunnel.c
** On Solaris:  cc -o tunnel tunnel.c -lnsl -lsocket
**
** Usage:   tunnel <Listen IP>    <Listen Port> <Remote IP>    <Remote Port>
** Example: tunnel 130.35.100.100 8123          130.35.100.101 80
**
** Requests inbound on 8123 will be sent to the remote IP:Port, and
** responses returned along the same path to the originating system.
*/

#ifdef WIN32

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#define os_objhand    HANDLE
#define os_socket     SOCKET
#define os_badsocket  INVALID_SOCKET

#else

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <malloc.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define os_objhand    int
#define os_socket     int
#define os_badsocket  -1

#endif

#define POLL_BLOCK_REQUEST  10000 /* up to 10 seconds */
#define POLL_BLOCK_RESPONSE    20 /* 20 milliseconds */

#ifdef WIN32

os_objhand file_open_write(char *fpath, int append_flag, int share_flag)
{
    os_objhand fh;
    int        flags = 0;
    if (share_flag) flags = FILE_SHARE_READ | FILE_SHARE_WRITE;
    fh = CreateFile(fpath, GENERIC_WRITE, flags,
                    0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (append_flag)
      if (fh != INVALID_HANDLE_VALUE)
        SetFilePointer(fh, 0, 0, FILE_END);
    return(fh);
}

int file_write_data(os_objhand fp, char *buffer, int buflen)
{
    DWORD nbytes;
    if (fp == INVALID_HANDLE_VALUE) return(-1);
    nbytes = (DWORD)buflen;
    if (!WriteFile(fp, buffer, nbytes, &nbytes, NULL)) return(-1);
    return((int)nbytes);
}

void file_close(os_objhand fp)
{
    if (fp != INVALID_HANDLE_VALUE) CloseHandle(fp);
}

#else

os_objhand file_open_write(char *fpath, int append_flag, int share_flag)
{
    os_objhand fd;
    int        flags = O_WRONLY | O_CREAT;
    if (append_flag) flags |= O_APPEND;
    fd = open(fpath, flags, 0600);
    return(fd);
}

int file_write_data(os_objhand fp, char *buffer, int buflen)
{
    int nbytes;
    if (fp < 0) return(-1);
    nbytes = write(fp, buffer, buflen);
    return(nbytes);
}

void file_close(os_objhand fp)
{
    if (fp >= 0) close(fp);
}

#endif

/*
** Socket initialization
*/
void socket_init(void)
{
#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2,0), &wsa_data); /* Winsock 2.0 */
#endif
}

/*
** Close a socket
*/
void socket_close(os_socket sock)
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
os_socket socket_listen(int port, char *ipaddr, int backlog)
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

    if (sfd != os_badsocket)
    {
        if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
        {
            socket_close(sfd);
            sfd = os_badsocket;
        }
        else if (listen(sfd, backlog) != 0)
        {
            socket_close(sfd);
            sfd = os_badsocket;
        }
    }

    return(sfd);
}

/*
** Accept a new socket connection
*/
os_socket socket_accept(os_socket sock)
{
    os_socket          sfd;
    struct sockaddr_in saddr;
    int                n;

    n = sizeof(saddr);
#ifdef WIN32
    FillMemory((void *)&saddr, (DWORD)n, (BYTE)0);
#else
    memset((void *)&saddr, 0, n);
#endif
    sfd = accept(sock, (struct sockaddr *)&saddr, &n);
    return(sfd);
}

/*
** Socket connect
*/
os_socket socket_connect(int port, char *ipaddr)
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
    if (sfd != os_badsocket)
    {
        if (connect(sfd, (struct sockaddr *)&saddr, sizeof(saddr)))
        {
            socket_close(sfd);
            sfd = os_badsocket;
        }
    }
    return(sfd);
}

/*
** Write to a socket
*/
int socket_write(os_socket sock, char *buffer, int buflen)
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
int socket_read(os_socket sock, char *buffer, int buflen)
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
** Check for input available on a set of sockets
*/
int socket_test(os_socket *sock, int nsock, int ms)
{
    int            i;
#ifdef WIN32
    fd_set         rfds;
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    FD_ZERO(&rfds);
    for (i = 0; i < nsock; ++i) FD_SET(sock[i], &rfds);

    if (select(0, &rfds, (fd_set *)0, (fd_set *)0, &tv))
    {
        if (nsock == 1) return(1);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        for (i = 0; i < nsock; ++i)
        {
            FD_ZERO(&rfds);
            FD_SET(sock[i], &rfds);
            if (select(0, &rfds, (fd_set *)0, (fd_set *)0, &tv)) return(i + 1);
        }
    }
#else
    struct pollfd pfd[10]; /* ### UNIX VERSION LIMITED TO 10 ### */

    i = sizeof(pfd)/sizeof(*pfd);
    if (nsock > i) nsock = i;

    for (i = 0; i < nsock; ++i)
    {
        pfd[i].fd = sock[i];
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
    }

    if (poll(pfd, nsock, ms))
      for (i = 0; i < nsock; ++i)
        if (pfd[i].revents == POLLIN) return(i + 1);
#endif
    return(0);
}

/*
** Arguments: <Listen IP> <Listen Port> <Remote IP> <Remote Port>
*/
int main(argc, argv)
int   argc;
char *argv[];
{
    os_socket   sock;
    int         port;
    os_socket   lsock;
    os_socket   asock;
    os_socket   poll_fds[2];
    int         first;
    int         lport;
    int         n;
    char       *lipaddr;
    char       *ipaddr;
    char        buffer[4096];
    os_objhand  fout;

    if (argc < 5)
    {
        printf("usage: %s %s %s %s %s\n", argv[0],
               "<Listen IP address>", "<Listen port number>",
               "<Remote IP address>", "<Remote port number>");
        return(0);
    }

    socket_init();

    /*
    ** Decode the arguments
    */
    lipaddr = argv[1];
    lport = atoi(argv[2]);
    ipaddr = argv[3];
    port = atoi(argv[4]);

    lsock = socket_listen(lport, lipaddr, 100);
    if (lsock < 0)
    {
        printf("Unable to listen on [%s:%d]\n", lipaddr, lport);
        return(1);
    }

    while (1)
    {
        printf("Ready to accept a request\n");
        asock = socket_accept(lsock);
        if (asock < 0)
        {
            printf("Error accepting request on [%s:%d]\n", lipaddr, lport);
            return(1);
        }
        printf("Accepted request\n");

        sock = socket_connect(port, ipaddr);
        if (sock < 0)
        {
            printf("Unable to connect to [%s:%d]\n", ipaddr, port);
            return(1);
        }

        printf("Connected to server\n");

        fout = file_open_write("tunnel.dat", 1, 0);
#ifdef WIN32
        if (fout == INVALID_HANDLE_VALUE)
#else
        if (fout < 0)
#endif
        {
            printf("Unable to open trace file\n");
            return(1);
        }

        printf("Request\n");

        n = sizeof(buffer);
        poll_fds[0] = asock;
        poll_fds[1] = sock;
        while (1)
        {
            first = socket_test(poll_fds, 2, POLL_BLOCK_REQUEST);
            if (first != 1) break;
            n = socket_read(asock, buffer, sizeof(buffer));
            if (n <= 0) break;
            printf("  Read block of %d bytes from requestor\n", n);
            file_write_data(fout, buffer, n);
            n = socket_write(sock, buffer, n);
            printf("  Wrote block of %d bytes to server\n", n);
            first = 1;
        }

        printf("Response\n");

        first = 0;
        n = sizeof(buffer);
        while (1)
        {
            if (!socket_test(&sock, 1, (first) ? POLL_BLOCK_RESPONSE :
                                                 POLL_BLOCK_REQUEST))
                break;
            n = socket_read(sock, buffer, sizeof(buffer));
            if (n <= 0) break;
            printf("  Read block of %d bytes from server\n", n);
            file_write_data(fout, buffer, n);
            n = socket_write(asock, buffer, n);
            printf("  Wrote block of %d bytes to requestor\n", n);
            first = 1;
        }

        if (!first) printf("Timed out waiting for server response\n");

        socket_close(asock);
        socket_close(sock);
        file_close(fout);
    }

    return(0);
}
