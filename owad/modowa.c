/*
** Copyright (c) 1999-2013 Oracle Corporation, All rights reserved.
**
**  Licensed under the Apache License, Version 2.0 (the "License");
**  you may not use this file except in compliance with the License.
**  You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
/*
** File:         modowa.c
** Description:  Apache module to support Oracle PL/SQL gateway (OWA).
** Authors:      Alvydas Gelzinis  alvydas@kada.lt
**               Oksana Kulikova   oksana@kada.lt
**               Doug McMahon      dmcmahon@us.oracle.com
**               Edward Jiang      edward.jiang@oracle.com
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** History
**
** 08/17/2000   D. McMahon      Created
** 05/31/2001   D. McMahon      Began revisioning with 1.3.9/2.3.9
** 06/16/2001   D. McMahon      Added support for RAW input/output bindings
** 09/01/2001   D. McMahon      Added OwaRound
** 09/07/2001   D. McMahon      Added TIMING diagnostic
** 09/13/2001   D. McMahon      Fixed parse problems with OwaReset
** 12/12/2001   D. McMahon      Add the code for OwaReject
** 01/03/2002   D. McMahon      Remove Apache 2.0 WIN32 work-arounds
** 01/08/2002   D. McMahon      Fix problems with Apache 2.0 callbacks
** 02/11/2002   D. McMahon      Add OwaDocFile
** 04/29/2002   D. McMahon      Return OK for Apache 2.0 hooks
** 05/17/2002   D. McMahon      Added OwaEnv
** 06/10/2002   D. McMahon      Fix mistakes with oracle_round/oracle_admin
** 06/11/2002   D. McMahon      Add THREADS mode to oracle_pool
** 07/22/2002   D. McMahon      Support flush for morq_write
** 08/08/2002   D. McMahon      Added hooks for DAV owa_dav_request
** 10/10/2002   D. McMahon      Add ERROR diagnostic flag
** 03/17/2003   D. McMahon      Add NOMERGE to OwaAlternate
** 06/06/2003   D. McMahon      Support special error page for SQL errors
** 01/19/2004   D. McMahon      Add sessioning support
** 02/14/2006   D. McMahon      Work around an Apache argument parsing bug
** 05/30/2006   D. McMahon      Apache 2.2 port
** 09/30/2006   D. McMahon      Protect cleanup thread from exit processing
** 02/02/2007   D. McMahon      Add OwaLDAP directive
** 04/12/2007   D. McMahon      Add OwaDocTable directive
** 05/11/2007   D. McMahon      Avoid Apache 2.x bug in set_mimetype
** 09/28/2007   D. McMahon      Omit headers processing for Apache 2.x
** 08/20/2008   C. Fischer      Added OwaWait and OwaOptmizer
** 02/22/2009   D. McMahon      Check Apache mpm threads
** 06/26/2009   D. McMahon      Fix a crash in morq_create_mutex
** 03/10/2010   D. McMahon      Add parens around str_to_mem
** 03/01/2011   D. McMahon      Fix multi-threading problems for Linux
** 04/19/2011   D. McMahon      Unscramble DB connect string (moved)
** 11/12/2011   D. McMahon      Add OwaCharsize
** 03/28/2012   D. McMahon      Add OwaContentType support
** 11/27/2012   D. McMahon      GCC fixes, Win-64 porting
** 02/25/2013   D. McMahon      Apache 2.4 version
** 04/12/2013   D. McMahon      Add support for REST operations
*/

#ifdef EAPI_ONLY /* Compile with new EAPI magic number */
# ifndef EAPI
#  define EAPI
# endif
#endif
#ifdef EAPI
# ifndef EAPI_ONLY
#  define USE_OLD_MAGIC
# endif
#endif

#ifdef APACHE24
# ifndef APACHE22
#  define APACHE22
# endif
#endif
#ifdef APACHE22
# ifndef APACHE20
#  define APACHE20
# endif
#endif

/*
** Apache headers
*/
#ifdef WIN64
# ifndef WIN32
# define WIN32 /* ### This works around define issues in Apache headers ### */
# endif
#endif
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_script.h>

#ifdef APACHE20

#include <apr.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>
#include <ap_mpm.h>
#ifdef APACHE22
#include <ap_regex.h>
#endif

#define OWA_MULTI_THREADED

#define LOGSTATUS(s)  (apr_status_t)0,(s)

#else

#include <multithread.h>

/* Define this for multi-threaded servers */
#ifdef MULTITHREAD
# define OWA_MULTI_THREADED
#endif

#define apr_pool_t         pool
#define apr_table_t        table
#define apr_size_t         int
#define apr_array_header_t array_header
#define apr_table_entry_t  table_entry
#define apr_pcalloc        ap_pcalloc
#define apr_palloc         ap_palloc
#define apr_pstrdup        ap_pstrdup
#define apr_table_unset    ap_table_unset
#define apr_table_set      ap_table_set
#define apr_table_add      ap_table_add
#define apr_table_get      ap_table_get
#define apr_table_elts     ap_table_elts
#define apr_table_clear    ap_clear_table

#define LOGSTATUS(s)  (s)

#endif

#define WITH_APACHE
#include <modowa.h>

/*
** ### THIS IS A KLUDGE: FOR SOME REASON, THE OCI CONNECT OPERATION
** ### LEAVES A NON-ZERO VALUE IN errno, WHICH THEN CAUSES JUNK TO
** ### PRINT TO THE VERY NEXT APACHE LOGGING OPERATION.
*/
#ifdef LINUX
# define CHECK_ERRNO
#endif
#ifdef SUN_OS5
# define CHECK_ERRNO
#endif

#ifdef OWA_MULTI_THREADED
#define MAX_WAIT   500                    /* Mutex timeout in milliseconds */
#define MAX_POOL   255                    /* Number of cached connections  */
#define MIN_POOL   10                     /* Number of cached connections  */
#else
#define MAX_POOL   1                      /* Unix is single-threaded       */
#define MIN_POOL   1                      /* Unix is single-threaded       */
#endif

#ifndef APACHE20
# define CLOSE_SOCKET_ON_EXEC
#endif

#ifdef APACHE20
static char modowa_version[] = "mod_owa 2.9.1";
#else
static char modowa_version[] = "mod_owa 1.9.1";
#endif

/*
** Module configuration
*/
typedef struct oracle_config
{
    char        *version;
    int          realpid;
    shm_context *mapmem;
    owa_context *loc_list;
    char        *data_buffer;
    os_objptr    o_mutex;
    int          tinterval;
    un_long      tid;
    os_thrhand   thand;
} oracle_config;

/*
** Sub-context for multi-threading support
*/
struct owa_mt_context
{
#ifdef APACHE20 /* ### NO NATIVE SUPPORT? ### */
    os_objptr    c_mutex;     /* Per-process connection pool latch */
    os_objptr    c_semaphore; /* Per-process connection pool queue */
#else
#ifdef OWA_MULTI_THREADED
    mutex       *c_mutex;
#ifdef MODOWA_WINDOWS
    HANDLE       c_semaphore; /* Apache doesn't have these yet */
#endif
#else
    os_objptr    t_mutex;     /* Cleanup thread mutex */
#endif
#endif
};

#ifdef APACHE20
AP_MODULE_DECLARE_DATA module owa_module;
#else
MODULE_VAR_EXPORT module owa_module;
#endif

#ifdef CHECK_ERRNO
#define RESET_ERRNO os_set_errno(0)
#else
#define RESET_ERRNO
#endif

/*****************************************************************************\
 * General Apache-based functions for external callers                       *
\*****************************************************************************/

int mowa_check_keepalive(int context_flag)
{
#ifdef MODOWA_WINDOWS
    /* Not a problem on Windows */
    return(1);
#else
# ifdef CLOSE_SOCKET_ON_EXEC
    return(1);
# else
#  ifdef OWA_MULTI_THREADED
    /*
    ** ### For Apache 2.0, there is no current solution; for now,
    ** ### content-length returns are completely disabled if you
    ** ### are using the bequeath adaptor (so don't use it!)
    */
    return((context_flag == OWA_KEEPALIVE_OK));
#  else
    /*
    ** On single-threaded Unix, this flag indicates recent launch of
    ** bequeath-based connection; if 0, unsafe to proceed
    */
    return((context_flag > OWA_KEEPALIVE_OFF));
#  endif
# endif
#endif
}

void mowa_acquire_mutex(owa_context *octx)
{
#ifdef APACHE20
    if (!InvalidMutex(octx->mtctx->c_mutex))
        os_mutex_acquire(octx->mtctx->c_mutex, SHMEM_WAIT_INFINITE);
#else
#ifdef OWA_MULTI_THREADED
    ap_acquire_mutex(octx->mtctx->c_mutex);
#else
    /* Latch the context area only if the cleanup thread is running */
    if (!InvalidMutex(octx->mtctx->t_mutex))
        os_mutex_acquire(octx->mtctx->t_mutex, SHMEM_WAIT_INFINITE);
#endif
#endif
}

void mowa_release_mutex(owa_context *octx)
{
#ifdef APACHE20
    if (!InvalidMutex(octx->mtctx->c_mutex))
        os_mutex_release(octx->mtctx->c_mutex);
#else
#ifdef OWA_MULTI_THREADED
    ap_release_mutex(octx->mtctx->c_mutex);
#else
    /* Unlatch the context area only if the cleanup thread is running */
    if (!InvalidMutex(octx->mtctx->t_mutex))
        os_mutex_release(octx->mtctx->t_mutex);
#endif
#endif
}

void mowa_semaphore_create(owa_context *octx)
{
#ifdef OWA_MULTI_THREADED
    if ((octx->poolsize > 0) && (octx->poolsize <= MAX_POOL))
        octx->mtctx->c_semaphore = os_cond_init((char *)0, octx->poolsize, 1);
#endif
}

int mowa_semaphore_get(owa_context *octx)
{
#ifdef OWA_MULTI_THREADED
    if ((octx->poolsize > 0) && (octx->poolsize <= MAX_POOL))
        return(os_cond_wait(octx->mtctx->c_semaphore, octx->pool_wait_ms));
#endif
    return(1);
}

void mowa_semaphore_put(owa_context *octx)
{
#ifdef OWA_MULTI_THREADED
    if ((octx->poolsize > 0) && (octx->poolsize <= MAX_POOL))
        os_cond_signal(octx->mtctx->c_semaphore);
#endif
}

/*****************************************************************************\
 * Request-based functions                                                   *
\*****************************************************************************/

void morq_create_mutex(request_rec *request, owa_context *octx)
{
#ifdef APACHE20
    server_rec    *s;
    volatile oracle_config *cfg;

    if (!(octx->multithread)) return;
    if (octx->mtctx->c_mutex != os_nullmutex) return;
    /*
    ** The first time, get the global mutex,
    ** then create the per-process connection pool latch
    */
    s = request->server;
    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
    {
      if (!(cfg->tinterval)) return;
      if (!InvalidMutex(cfg->o_mutex))
        os_mutex_acquire(cfg->o_mutex, SHMEM_WAIT_INFINITE);
    }
    if (InvalidMutex(octx->mtctx->c_mutex))
        octx->mtctx->c_mutex = os_mutex_create((char *)0, 1);
    if (cfg)
      if (!InvalidMutex(cfg->o_mutex))
        os_mutex_release(cfg->o_mutex);
#endif
}

char *morq_get_buffer(request_rec *request, int sz)
{
#ifndef OWA_MULTI_THREADED
    server_rec    *s = request->server;
    oracle_config *cfg;
    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (sz <= HTBUF_ARRAY_SIZE * HTBUF_LINE_LENGTH) return(cfg->data_buffer);
#endif
    return((char *)0);
}

void *morq_alloc(request_rec *request, int sz, int zero_flag)
{
    if (zero_flag) return(apr_pcalloc(request->pool, sz));
    return(apr_palloc(request->pool, sz));
}

int morq_regex(request_rec *request, char *pattern, char **str, int caseflag)
{
#ifdef APACHE22
    ap_regex_t    *rules;
    ap_regmatch_t  match;
#else
    regex_t    *rules;
    regmatch_t  match;
#endif
    int         flags;

#ifdef APACHE22
    flags = AP_REG_EXTENDED;
    if (caseflag) flags |= AP_REG_ICASE;
#else
    flags = REG_EXTENDED;
    if (caseflag) flags |= REG_ICASE;
#endif

    rules = ap_pregcomp(request->pool, pattern, flags);
    if (!rules) return(0);
    if (ap_regexec(rules, *str, 1, &match, 0)) return(0);
    *str += match.rm_so;
    return((int)(match.rm_eo - match.rm_so));
}

void morq_send_header(request_rec *request)
{
#ifndef APACHE20 /* ### Appears to be a NO-OP in 2.0 ### */
    ap_send_http_header(request);
#endif
}

void morq_set_status(request_rec *request, int status)
{
    request->status = status;
}

void morq_set_mimetype(request_rec *request, char *mtype)
{
    char *sptr;
    int   slen;

    if (mtype)
    {
        /* Duplicate the string to avoid an Apache 2.x send-header bug */
        slen = str_length(mtype) + 1;
        sptr = apr_palloc(request->pool, slen);
        if (sptr)
        {
            mem_copy(sptr, mtype, slen);
            mtype = sptr;
        }
    }

    request->content_type = mtype;
}

void morq_set_length(request_rec *request, long len, int range_flag)
{
    if (range_flag)  request->clength = len;
    else             ap_set_content_length(request, len);
}

int morq_check_range(request_rec *request)
{
#ifdef APACHE20
    return(0); /* ### NEED NEW IMPLEMENTATION ### */
#else
    return(ap_set_byterange(request));
#endif
}

int morq_get_range(request_rec *request, long *off, long *len)
{
#ifdef APACHE20
    return(0); /* ### NEED NEW IMPLEMENTATION ### */
#else
    return(ap_each_byterange(request, off, len));
#endif
}

char *morq_getword(request_rec *request,
                   const char **args, char ch, int un_escape)
{
    char *sptr;
    char *aptr;
    int   sz;

    /*
    ** Work-around for Apache parsing bug.  The problem is that
    ** ap_getword will not stop at the first match to the specified
    ** search character.  Instead, it will consume all matching
    ** values.  This is probably what you want when you are looking
    ** for an '&' separating two arguments, but it's not correct
    ** when looking for the '=' that separates an argument name
    ** from an argument value (since the value might itself begin
    ** with the '=' sign).  In theory the '=' should be escaped but
    ** some apps don't do this properly.  The work-around first
    ** attempts to detect the condition that causes failure, and
    ** if so, it does its own parse in lieu of Apache's.  If not,
    ** it follows the original code path.
    */
    aptr = (char *)0;
    if ((*args != (char *)0) && (ch == '='))
    {
        sptr = str_char(*args, ch, 0);
        if (sptr)
        {
            if (sptr[1] == ch)
            {
                /* This is the case where Apache's parser fails */
                sz = (int)(sptr - *args);
                aptr = apr_palloc(request->pool, sz + 1);
                if (aptr)
                {
                    memcpy(aptr, *args, sz);
                    aptr[sz] = '\0';
                    *args = (sptr + 1);
                }
            }
        }
    }

    if (!aptr)
        if (*args != (char *)0)
            aptr = ap_getword(request->pool, args, ch);
    if (!aptr) aptr = (char *)"";
    if ((un_escape) && (*aptr != '\0'))
    {
        for (sptr = aptr; *sptr != '\0'; ++sptr)
            if (*sptr == '+') *sptr = ' ';
        ap_unescape_url(aptr);
    }

    return(aptr);
}

int morq_stream(request_rec *request, int flush_flag)
{
    int status;
    if (flush_flag) return(ap_discard_request_body(request));
    status = ap_setup_client_block(request, REQUEST_CHUNKED_DECHUNK);
    if (!status) status = (ap_should_client_block(request)) ? 0 : -1;
    return(status);
}

long morq_read(request_rec *request, char *buffer, long buflen)
{
    long nbytes;
    nbytes = (long)ap_get_client_block(request, buffer, (apr_size_t)buflen);
    if (nbytes == 0) nbytes = -1;
    return(nbytes);
}

long morq_write(request_rec *request, char *buffer, long buflen)
{
    if (!buffer)
    {
        ap_rflush(request);
        return(0);
    }

    if (buflen < 0) buflen = str_length(buffer);
    ap_rwrite(buffer, (int)buflen, request);
    return(buflen);
}

void morq_print_int(request_rec *request, char *fmt, long ival)
{
    ap_rprintf(request, fmt, ival);
}

void morq_print_str(request_rec *request, char *fmt, char *sptr)
{
    ap_rprintf(request, fmt, sptr);
}

int  morq_table_get(request_rec *request, int tableid, int index,
                    char **name, char **value)
{
    apr_array_header_t *arr;
    apr_table_entry_t  *elements;
    int                 nelements;

    switch (tableid)
    {
    case OWA_TABLE_SUBPROC:
        arr = (apr_array_header_t *)apr_table_elts(request->subprocess_env);
        break;
    case OWA_TABLE_HEADIN:
        arr = (apr_array_header_t *)apr_table_elts(request->headers_in);
        break;
    default:
        return(0);
        break;
    }

    elements = (apr_table_entry_t *)(arr->elts);
    nelements = arr->nelts;

    if (index < nelements)
    {
        *name  = elements[index].key;
        *value = elements[index].val;
        return(1);
    }

    return(0);
}

void morq_table_put(request_rec *request, int tableid, int set_flag,
                    char *name, char *value)
{
    apr_table_t *tab;

    switch (tableid)
    {
    case OWA_TABLE_SUBPROC:  tab = request->subprocess_env;  break;
    case OWA_TABLE_HEADOUT:  tab = request->headers_out;     break;
    case OWA_TABLE_HEADERR:  tab = request->err_headers_out; break;
    default:                 return;                         break;
    }

    if (set_flag) apr_table_set(tab, name, value);
    else          apr_table_add(tab, name, value);
}

char *morq_get_header(request_rec *request, char *name)
{
    return((char *)apr_table_get(request->headers_in, name));
}

char *morq_get_env(request_rec *request, char *name)
{
    return((char *)apr_table_get(request->subprocess_env, name));
}

char *morq_parse_auth(request_rec *request, char *buffer)
{
    char *sptr;
    char *aptr;
    int   len;

    len = str_length(buffer);
    sptr = (char *)apr_palloc(request->pool, len + 4);
    if (!sptr) return((char *)"");
    mem_copy(sptr, buffer, len + 1);
    aptr = str_char(buffer, ' ', 0);
    if (aptr)
    {
        ++aptr;
        util_decode64(aptr, sptr + (aptr - buffer));
    }
    return(sptr);
}

void morq_add_context(request_rec *request, owa_context *octx)
{
    server_rec    *s = request->server;
    volatile oracle_config *cfg;
    int            latch;

    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
    {
        octx->realpid = cfg->realpid;
#ifndef OWA_MULTI_THREADED
        /*
        ** Create a mutex used only by the cleanup thread;
        ** do this before adding the structure to the linked
        ** list, which makes it visible to cleanup.  This
        ** mutex is private to the process.  After creation,
        ** acquire it, because the caller is going to release
        ** it later (the caller already executed acquire, which
        ** was a no-op at the time).
        */
        if (!InvalidThread(cfg->thand))
        {
            octx->mtctx->t_mutex = os_mutex_create((char *)0, 1);
            if (!InvalidMutex(octx->mtctx->t_mutex))
                mowa_acquire_mutex(octx);
        }
#endif

        if (InvalidMutex(cfg->o_mutex))
            latch = 1;
        else  /* Latch the config structure */
            latch = os_mutex_acquire(cfg->o_mutex, SHMEM_WAIT_INFINITE);

        if (latch)
        {
            octx->next = cfg->loc_list;
            octx->mapmem = cfg->mapmem;
            cfg->loc_list = octx;

            if (!InvalidMutex(cfg->o_mutex)) os_mutex_release(cfg->o_mutex);
        }
    }
    else
        octx->realpid = os_get_pid();
}

void morq_close_exec(request_rec *request, owa_context *octx, int first_flag)
{
#ifndef MODOWA_WINDOWS
#ifdef CLOSE_SOCKET_ON_EXEC
#ifndef OWA_MULTI_THREADED
    if ((first_flag) && (octx->keepalive_flag != OWA_KEEPALIVE_OK))
#endif
    {
      os_fd_close_exec(request->connection->client->fd);
      if (request->connection->client->fd !=
          request->connection->client->fd_in)
        os_fd_close_exec(request->connection->client->fd_in);
    }
#else /* !CLOSE_SOCKET_ON_EXEC */
    if (first_flag)
    {
        if (octx->keepalive_flag == OWA_KEEPALIVE_ON)
            octx->keepalive_flag = OWA_KEEPALIVE_OFF;
    }
    else
    {
        if (octx->keepalive_flag == OWA_KEEPALIVE_OFF)
            octx->keepalive_flag = OWA_KEEPALIVE_ON;
    }
#endif /* !CLOSE_SOCKET_ON_EXEC */
#endif /* !MODOWA_WINDOWS */
}

void morq_sql_error(request_rec *request,
                    int code, char *errbuf, char *lastsql)
{
    int         i;
    server_rec *s = request->server;

    RESET_ERRNO;
    ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                 "SQL error %d", code);

    if (*errbuf != '\0')
    {
        i = str_length(errbuf);
        if (errbuf[--i] == '\n') errbuf[i] = '\0';
        ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                     "\n%s", errbuf);
    }

    if (lastsql)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                     "The last SQL statement executed was:\n%s", lastsql);
    }
}

/*****************************************************************************\
 * Linkage to Apache                                                         *
\*****************************************************************************/

/*
** Main loop for the cleanup thread
*/
static void oracle_thread(void *tctx)
{
    volatile oracle_config *cfg = (oracle_config *)tctx;
    volatile owa_context   *octx;
    int                     t;

    thread_block_signals();

    while (cfg->tinterval > 0)
    {
        thread_check();
        if (!InvalidMutex(cfg->o_mutex)) /* Latch the config structure */
          if (os_mutex_acquire(cfg->o_mutex, SHMEM_WAIT_MAX))
          {
            /*
            ** Copy the first context on the list in case a new one
            ** is added while the cleanup thread is running.  This
            ** allows the mutex to be released quickly.
            */
            octx = cfg->loc_list;
            t    = cfg->tinterval;

            if (!InvalidMutex(cfg->o_mutex))
                os_mutex_release(cfg->o_mutex);
 
            /*
            ** ### There is some possibility that exit
            ** ### processing is being done while this loop
            ** ### is running.  To minimize the changes for
            ** ### conflicts, check tinterval and init_complete.
            */
            while ((octx) && (cfg->tinterval > 0))
            {
                thread_check();
                if (octx->init_complete)
                    owa_pool_purge((owa_context *)octx, t);
#ifndef NO_FILE_CACHE
                if (octx->init_complete)
                    owa_file_purge((owa_context *)octx, t);
#endif
                octx = octx->next;
            }
          }

        t = cfg->tinterval;
        if (t < 1000000) t *= 1000;
        os_milli_sleep(t);
    }
    thread_exit();
}

static const char *alloc_failure(server_rec *s, int sz)
{
    RESET_ERRNO;
    ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                 "PID %d error allocating %d bytes", os_get_pid(), sz);
    return((char *)0); /* ### Should return DECLINE_CMD? */
}

static int get_dav_method(int m)
{
  int x = -1; /* Unknown or unsupported */
  switch(m)
  {
  case M_GET:              x = DAV_METHOD_GET;              break;
  case M_PUT:              x = DAV_METHOD_PUT;              break;
  case M_POST:             x = DAV_METHOD_POST;             break;
  case M_DELETE:           x = DAV_METHOD_DELETE;           break;

  /* DAV methods */
  case M_CONNECT:          x = DAV_METHOD_CONNECT;          break;
  case M_OPTIONS:          x = DAV_METHOD_OPTIONS;          break;
  case M_TRACE:            x = DAV_METHOD_TRACE;            break;
  case M_PATCH:            x = DAV_METHOD_PATCH;            break;
  case M_PROPFIND:         x = DAV_METHOD_PROPFIND;         break;
  case M_PROPPATCH:        x = DAV_METHOD_PROPPATCH;        break;
  case M_MKCOL:            x = DAV_METHOD_MKCOL;            break;
  case M_COPY:             x = DAV_METHOD_COPY;             break;
  case M_MOVE:             x = DAV_METHOD_MOVE;             break;
  case M_LOCK:             x = DAV_METHOD_LOCK;             break;
  case M_UNLOCK:           x = DAV_METHOD_UNLOCK;           break;

#ifdef APACHE20
  /* Extended DAV methods (not available in Apache 1.3) */
  case M_VERSION_CONTROL:  x = DAV_METHOD_VERSION_CONTROL;  break;
  case M_CHECKOUT:         x = DAV_METHOD_CHECKOUT;         break;
  case M_UNCHECKOUT:       x = DAV_METHOD_UNCHECKOUT;       break;
  case M_CHECKIN:          x = DAV_METHOD_CHECKIN;          break;
  case M_UPDATE:           x = DAV_METHOD_UPDATE;           break;
  case M_LABEL:            x = DAV_METHOD_LABEL;            break;
  case M_REPORT:           x = DAV_METHOD_REPORT;           break;
  case M_MKWORKSPACE:      x = DAV_METHOD_MKWORKSPACE;      break;
  case M_MKACTIVITY:       x = DAV_METHOD_MKACTIVITY;       break;
  case M_BASELINE_CONTROL: x = DAV_METHOD_BASELINE_CONTROL; break;
  case M_MERGE:            x = DAV_METHOD_MERGE;            break;
#endif
  default:
    break;
  }
  return(x);
}
  
static int mowa_handler(request_rec *r)
{
    int          result;
    int          post_flag;
    double       t1, t2;
    owa_context *octx;
    owa_request  owa_req;

#ifdef APACHE20
    if (str_compare(r->handler, "owa_handler", -1, 1)) return(DECLINED);
#endif

    mem_zero(&owa_req, sizeof(owa_req));

    result = OK;

    octx = (owa_context *)ap_get_module_config(r->per_dir_config, &owa_module);

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

#ifndef APACHE20 /* ### NO REPLACEMENT IN 2.0? ### */
    ap_soft_timeout((char *)"send a2o call trace", r);
#endif

    r->status = HTTP_OK; /* Default is OK */

#ifndef APACHE20
    /*
    ** Under Apache 2.0 and later, Apache expects the full request to make
    ** sure that headers are consistent between GET and HEAD requests. See
    ** http://perl.apache.org/docs/2.0/user/handlers/http.html for more
    ** information and links to the Apache source mentioning this expectation.
    */
    if (r->header_only)
    {
        /* Nothing to do, so just send header */
        r->content_type = (char *)"text/plain";
        morq_send_header(r);
    }
    else
#endif
    {
        RESET_ERRNO;
        ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(r->server),
                     "OWA Request [%s]", r->uri);

        post_flag = get_dav_method(r->method_number);
        result = owa_handle_request(octx, r, r->args, post_flag, &owa_req);

        RESET_ERRNO;
        /* ### Revisit the use of floating-point below ### */
        t1 = (double)(owa_req.wait_time/1000.0);
        t2 = (double)((owa_req.connect_time - owa_req.lock_time)/1000.0);
        ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(r->server),
                     "OWA Completed with status %d (%.3lf, %.3lf)",
                     result, t1, t2);
    }

#ifndef APACHE20 /* ### NO REPLACEMENT IN 2.0? ### */
    ap_kill_timeout(r);
#endif
    return(result);
}

static int str_to_mem(char *sptr)
{
    int sz = 0;
    while ((*sptr >= '0') && (*sptr <= '9'))
        sz = sz * 10 + (*(sptr++) - '0');
    if ((*sptr == 'k') || (*sptr == 'K')) sz *= 1024;
    if ((*sptr == 'm') || (*sptr == 'M')) sz *= (1024*1024);
    if ((*sptr == 'g') || (*sptr == 'G')) sz *= (1024*1024*1024);
    return(sz);
}

static int str_to_tim(char *sptr)
{
    int tm = 0;
    while ((*sptr >= '0') && (*sptr <= '9'))
        tm = tm * 10 + (*(sptr++) - '0');
    while (*sptr == ' ') ++sptr;
    if ((*sptr == 'd') || (*sptr == 'D')) tm *= (60*60*24);
    if ((*sptr == 'h') || (*sptr == 'H')) tm *= (60*60);
    if ((*sptr == 'm') || (*sptr == 'M')) tm *= 60;
    return(tm);
}

static const char *mowa_diag(cmd_parms *cmd, owa_context *octx, char *dstr)
{
    int diagflag;

    /*
    ** Parse and set the diagnostic flags
    */
    if (dstr)
    {
        diagflag = 0;
        if (str_substr(dstr, "COMMAND",  1)) diagflag |= DIAG_COMMAND;
        if (str_substr(dstr, "ARGS",     1)) diagflag |= DIAG_ARGS;
        if (str_substr(dstr, "CGIENV",   1)) diagflag |= DIAG_CGIENV;
        if (str_substr(dstr, "POOL",     1)) diagflag |= DIAG_POOL;
        if (str_substr(dstr, "HEADER",   1)) diagflag |= DIAG_HEADER;
        if (str_substr(dstr, "COOKIES",  1)) diagflag |= DIAG_COOKIES;
        if (str_substr(dstr, "CONTENT",  1)) diagflag |= DIAG_CONTENT;
        if (str_substr(dstr, "RESPONSE", 1)) diagflag |= DIAG_RESPONSE;
        if (str_substr(dstr, "TIMING",   1)) diagflag |= DIAG_TIMING;
        if (str_substr(dstr, "SQL",      1)) diagflag |= DIAG_SQL;
        if (str_substr(dstr, "MEMORY",   1)) diagflag |= DIAG_MEMORY;
        if (str_substr(dstr, "THREADS",  1)) diagflag |= DIAG_THREADS;
        if (str_substr(dstr, "ERROR",    1)) diagflag |= DIAG_ERROR;
        octx->diagflag |= diagflag;
    }

    return((char *)0);
}

static const char *mowa_desc(cmd_parms *cmd, owa_context *octx,
                             char *dstr, char *schema)
{
    /*
    ** Parse and set the describe mode and schema
    */
    if (dstr)
    {
        if (!str_compare(dstr, "STRICT", -1, 1))
            octx->descmode = DESC_MODE_STRICT;
        else if (!str_compare(dstr, "NORMAL", -1, 1))
            octx->descmode = DESC_MODE_NORMAL;
        else if (!str_compare(dstr, "RELAXED", -1, 1))
            octx->descmode = DESC_MODE_RELAXED;
        else
            octx->desc_schema = dstr;
    }
    if (schema) octx->desc_schema = schema;

    return((char *)0);
}

static const char *mowa_alt(cmd_parms *cmd, owa_context *octx, char *astr)
{
    /*
    ** Set up alternate OWA package name and optional flags
    */
    if (astr)
    {
        if (octx->alternate == (char *)0)
            octx->alternate = astr;
        else if (str_substr(astr, "KEEPSTATE",  1))
            octx->altflags |= ALT_MODE_KEEP;
        else if (str_substr(astr, "WITHRAW",  1))
            octx->altflags |= ALT_MODE_RAW;
#ifndef ORACLE7
        else if (str_substr(astr, "USELOBS",  1))
            octx->altflags |= ALT_MODE_LOBS;
#endif
#ifndef NO_FILE_CACHE
        else if (str_substr(astr, "CACHE", 1))
            octx->altflags |= ALT_MODE_CACHE;
#endif
        else if (str_substr(astr, "SETSEC",  1))
            octx->altflags |= ALT_MODE_SETSEC;
        else if (str_substr(astr, "GETRAW",  1))
            octx->altflags |= ALT_MODE_GETRAW;
        else if (str_substr(astr, "NOMERGE",  1))
            octx->altflags |= ALT_MODE_NOMERGE;
        else if (str_substr(astr, "LOGGING",  1))
            octx->altflags |= ALT_MODE_LOGGING;
        else if (str_substr(astr, "CGITIME",  1))
            octx->altflags |= ALT_MODE_CGITIME;
        else if (str_substr(astr, "CGIPOST",  1))
            octx->altflags |= ALT_MODE_CGIPOST;
    }

    return((char *)0);
}

static const char *mowa_uni(cmd_parms *cmd, owa_context *octx, char *astr)
{
    /*
    ** Set up NCHAR binding support
    */
    if (astr)
    {
#ifndef ORACLE7
        if (str_substr(astr, "USER",  1))
            octx->ncflag = UNI_MODE_USER;
        else if (str_substr(astr, "FULL",  1))
            octx->ncflag = UNI_MODE_FULL;
        else if (str_substr(astr, "RAW",  1))
            octx->ncflag = UNI_MODE_RAW;
#endif
    }

    return((char *)0);
}

static const char *mowa_rset(cmd_parms *cmd, owa_context *octx, char *astr)
{
    if (astr)
    {
        if (!str_compare(astr, "FULL",  -1, 1))
            octx->rsetflag = RSET_MODE_FULL;
        else if (!str_compare(astr, "LAZY",  -1, 1))
            octx->rsetflag = RSET_MODE_LAZY;
        else if (!str_compare(astr, "INIT",  -1, 1))
            octx->rsetflag = RSET_MODE_INIT;
    }

    return((char *)0);
}

static const char *mowa_ver(cmd_parms *cmd, owa_context *octx,
                            char *vauth, char *pkg)
{
    /*
    ** Default is no authorization
    ** Older versions of OWA use OWA_INIT.AUTHORIZE
    ** Newer versions of OWA require OWA_CUSTOM.AUTHORIZE
    ** PACKAGE indicates a per-package authorization is required
    */

    if (vauth)
    {
        if (str_substr(vauth, "OWA_INIT", 1))
        {
            octx->version &= ~OWA_AUTH_CUSTOM;
            octx->version |= OWA_AUTH_INIT;
        }
        else if (str_substr(vauth, "OWA_CUSTOM", 1))
        {
            octx->version &= ~OWA_AUTH_INIT;
            octx->version |= OWA_AUTH_CUSTOM;
        }
        if (str_substr(vauth, "PACKAGE", 1))
            octx->version |= OWA_AUTH_PACKAGE;
    }

    if (pkg)
    {
        if (!str_compare(pkg, "PACKAGE", -1, 1))
            octx->version |= OWA_AUTH_PACKAGE;
    }

    return((char *)0);
}

static const char *mowa_ctype(cmd_parms *cmd, owa_context *octx,
                              char *ctype, char *ectype)
{
    if (ctype)
      if (*ctype)
        octx->default_ctype = ctype;
    if (ectype)
      if (*ectype)
        octx->error_ctype = ectype;

    return((char *)0);
}

static const char *mowa_dad(cmd_parms *cmd, owa_context *octx, char *odad)
{
    int i;

    if (odad)
    {
        i = nls_csx_from_iana(odad);
#ifndef ORACLE7
        if (i > 0) octx->dad_csid = i;
#endif
    }

    return((char *)0);
}

static const char *mowa_nls(cmd_parms *cmd, owa_context *octx, char *onls)
{
    int   i;
    char *aptr;
    char *bptr;

    if (onls)
    {
        /*
        ** Check NLS parameter for
        ** "." separating character set and "_" separating territory
        */
        aptr = str_char(onls, '.', 0);
        bptr = str_char(onls, '_', 0);

        if (aptr)
        {
            /* "." found, so character set points into original string */
            if (bptr)
                if (aptr < bptr)
                    bptr = (char *)0;
            i = (int)(aptr - onls);
            octx->nls_cs = ++aptr;
        }
        else if (bptr)
        {
            /* "_" found, so need to parse the string */
            i = str_length(onls);
        }
        else
        {
            /* string is just the character set, no parse needed */
            octx->nls_cs = onls;
            i = 0;
        }

        if (i > 0)
        {
            ++i;
            aptr = (char *)apr_palloc(cmd->pool, i);
            if (!aptr) return(alloc_failure(cmd->server, i));
            mem_copy(aptr, onls, i);
            aptr[i - 1] = '\0';

            octx->nls_lang = aptr;
            if (bptr)
            {
                bptr = aptr + (bptr - onls);
                *(bptr++) = '\0';
                octx->nls_terr = bptr;
            }
        }
    }

    return((char *)0);
}

static const char *mowa_upmx(cmd_parms *cmd, owa_context *octx, char *umaxstr)
{
    /*
    ** Set the content upload maximum
    */
    octx->upmax = (umaxstr) ? str_to_mem(umaxstr) : 0;

    return((char *)0);
}

static const char *mowa_pool(cmd_parms *cmd, owa_context *octx, char *poolstr)
{
    int         poolsize;
    int         oldsize;
    int         psize;
    char       *sptr;
    connection *cpool;

    if (poolstr)
    {
        if (str_compare(poolstr, "THREADS", -1, 1) == 0)
            poolsize = MAX_POOL + 1;
        else
        {
            poolsize = 0;
            for (sptr = poolstr; ((*sptr >= '0') && (*sptr <= '9')); ++sptr)
                poolsize = poolsize * 10 + (*sptr - '0');
            if (poolsize > MAX_POOL) poolsize = MAX_POOL;
        }
        oldsize = octx->poolsize;
        if (oldsize < MIN_POOL) oldsize = MIN_POOL;
        if (poolsize > oldsize)
        {
            psize = sql_conn_size(poolsize);
            cpool = (connection *)apr_pcalloc(cmd->pool, psize);
            if (cpool)
            {
                octx->poolsize = poolsize;
                octx->c_pool = cpool;
            }
        }
        else
        {
            octx->poolsize = poolsize;
        }
    }

    return((char *)0);
}

static const char *mowa_wait(cmd_parms *cmd, owa_context *octx,
                             char *waitstr, char *abortstr)
{
    int   wait_ms;
    char *sptr;

    if (waitstr)
    {
        wait_ms = 0;

        for (sptr = waitstr; ((*sptr >= '0') && (*sptr <= '9')); ++sptr)
            wait_ms = wait_ms * 10 + (*sptr - '0');

        octx->pool_wait_ms = wait_ms;
    }

    if (abortstr) octx->pool_wait_abort = 1;

    return((char *)0);
}

static const char *mowa_uid(cmd_parms *cmd, owa_context *octx, char *uid)
{
    char *sptr;

    if (uid)
    { 
        char *scramble = os_env_get("MODOWA_SCRAMBLE");
        if ((scramble) && (!str_char(uid, '/', 0) && !str_char(uid, '@', 0)))
        {
          int   klen = str_length(scramble);
          int   slen = str_length(uid);
          char *binstr = (char *)os_alloca(slen + 1);
          char *tempstr = (char *)apr_pcalloc(cmd->pool, slen + 1);
          slen = str_xtob(uid, (void *)binstr);
          if (util_scramble(scramble, klen, binstr, slen, tempstr, 1))
            uid = tempstr + 4; /* Skip the salt */
        }
        octx->oracle_userid = uid;
        for (sptr = uid; *sptr != '\0'; ++sptr)
            if (*sptr == '@')
            {
                /* OK to send content-lengths */
                octx->keepalive_flag = OWA_KEEPALIVE_OK;
                break;
            }
    }

    return((char *)0);
}

static const char *mowa_lobs(cmd_parms *cmd, owa_context *octx, char *ltypes)
{
    int lobtypes = 0;

    if (ltypes)
    {
        if (str_substr(ltypes,"BIN",  1)) lobtypes = LOB_MODE_BIN;
        if (str_substr(ltypes,"CHAR", 1)) lobtypes = LOB_MODE_CHAR;
        if (str_substr(ltypes,"NCHAR",1)) lobtypes = LOB_MODE_NCHAR;
        if (str_substr(ltypes,"FILE", 1)) lobtypes = LOB_MODE_BFILE;
        if (lobtypes > octx->lobtypes) octx->lobtypes = lobtypes;

        if (str_substr(ltypes, "LONG_RETURN_LENGTH", 1))
            octx->lontypes = LONG_MODE_RETURN_LEN;
        else if (str_substr(ltypes, "LONG_FETCH_LENGTH", 1))
            octx->lontypes = LONG_MODE_FETCH_LEN;
    }

    return((char *)0);
}

static const char *mowa_cache(cmd_parms *cmd, owa_context *octx,
                              char *logname, char *physname, char *life)
{
    un_long  life_seconds;
    alias   *new_lifes;
    alias   *old_lifes;
    int      i, j, n;

    /*
    ** Table of aliases that direct modowa to read physical files
    ** by translating logical path names; the idea is to allow modowa
    ** to track accesses to physical files, and also to allow modowa
    ** to project files from the database out to a file-system cache.
    ** The table is of the form:
    **   logname  = <Logical (URL) name>
    **   physname = <physical (file system) name>
    **   lifespan = <number of seconds>
    ** The table is reverse-alphabetically ordered so that longer
    ** paths will appear first (thus ensuring a match against the
    ** deepest applicable mapping later).
    */

    old_lifes = octx->lifes;
    n = octx->nlifes;
    if ((n % CACHE_MAX_ALIASES) == 0)
    {
        /* Extend the table by reallocation */
        n += CACHE_MAX_ALIASES;
        new_lifes = (alias *)apr_palloc(cmd->pool, n * sizeof(alias));
        if (!new_lifes) return(alloc_failure(cmd->server, n * sizeof(alias)));
        octx->lifes = new_lifes;
    }
    else
        new_lifes = old_lifes;

    life_seconds = 0;
    if (life)
      if (*life)
      {
          life_seconds = str_to_tim(life);
          if (life_seconds == 0) life_seconds = CACHE_DEF_LIFE;
      }

    n = (octx->nlifes++);

    for (i = 0; i < n; ++i)
    {
        /* if (s1 < s2), returns -1 */
        if (str_compare(old_lifes[i].logname, logname, -1, 1) < 0)
        {
            for (j = n; j > i; --j)
            {
                new_lifes[j].logname  = old_lifes[j - 1].logname;
                new_lifes[j].physname = old_lifes[j - 1].physname;
                new_lifes[j].lifespan = old_lifes[j - 1].lifespan;
            }
            break;
        }
        else if (new_lifes != old_lifes)
        {
            new_lifes[i].logname  = old_lifes[i].logname;
            new_lifes[i].physname = old_lifes[i].physname;
            new_lifes[i].lifespan = old_lifes[i].lifespan;
        }
    }
    new_lifes[i].logname  = logname;
    new_lifes[i].physname = physname;
    new_lifes[i].lifespan = life_seconds;

    return((char *)0);
}

static const char *mowa_http(cmd_parms *cmd, owa_context *octx, char *mode)
{
    if (mode)
    {
        if      (str_compare(mode, "NORMAL", -1, 1) == 0) octx->dav_mode = 0;
        else if (str_compare(mode, "REST", -1, 1) == 0)   octx->dav_mode = 1;
        else if (str_compare(mode, "DAV", -1, 1) == 0)    octx->dav_mode = 2;
    }
    return((char *)0);
}

static const char *mowa_flex(cmd_parms *cmd, owa_context *octx, char *flexname)
{
    char **new_flexes;
    char **old_flexes;
    int    i, n;

    if (flexname)
    {
        old_flexes = octx->flexprocs;
        n = octx->nflex;

        if ((n % CACHE_MAX_ALIASES) == 0)
        {
            i = (n + CACHE_MAX_ALIASES) * sizeof(*new_flexes);
            new_flexes = (char **)apr_palloc(cmd->pool, i);
            if (!new_flexes) return(alloc_failure(cmd->server, i));

            octx->flexprocs = new_flexes;
            for (i = 0; i < n; ++i) new_flexes[i] = old_flexes[i];
            old_flexes = new_flexes;
        }

        old_flexes[n++] = flexname;
        octx->nflex = n;
    }

    return((char *)0);
}

static const char *mowa_reject(cmd_parms *cmd, owa_context *octx, char *rname)
{
    char **new_rejs;
    char **old_rejs;
    int    i, n;

    if (rname)
    {
        old_rejs = octx->rejectprocs;
        n = octx->nreject;

        if ((n % CACHE_MAX_ALIASES) == 0)
        {
            i = (n + CACHE_MAX_ALIASES) * sizeof(*new_rejs);
            new_rejs = (char **)apr_palloc(cmd->pool, i);
            if (!new_rejs) return(alloc_failure(cmd->server, i));

            octx->rejectprocs = new_rejs;
            for (i = 0; i < n; ++i) new_rejs[i] = old_rejs[i];
            old_rejs = new_rejs;
        }

        old_rejs[n++] = rname;
        octx->nreject = n;
    }

    return((char *)0);
}

static const char *mowa_env(cmd_parms *cmd, owa_context *octx,
                            char *ename, char *evalue)
{
    envstruct *new_envs;
    envstruct *old_envs;
    int      i, n;

    if ((ename) && (evalue))
    {
        old_envs = octx->envvars;
        n = octx->nenvs;
        if ((n % CACHE_MAX_ALIASES) == 0)
        {
            /* Extend the table by reallocation */
            i = (n + CACHE_MAX_ALIASES) * sizeof(*new_envs);
            new_envs = (envstruct *)apr_palloc(cmd->pool, i);
            if (!new_envs) return(alloc_failure(cmd->server, i));
            octx->envvars = new_envs;
            for (i = 0; i < n; ++i) new_envs[i] = old_envs[i];
            old_envs = new_envs;
        }

        old_envs[n].name = ename;
        old_envs[n].value = evalue;
        ++(octx->nenvs);
    }

    return((char *)0);
}

static const char *mowa_crtl(cmd_parms *cmd, owa_context *octx,
                             char *ipsubnet, char *ipmask)
{
    un_long ip;

    if (ipsubnet)
    {
        ip = util_ipaddr(ipsubnet);
        octx->crtl_subnet = ip;
        octx->crtl_mask = ~((un_long)0);
    }
    if (ipmask)
    {
        ip = util_ipaddr(ipmask);
        octx->crtl_mask = ip;
    }
    return((char *)0);
}

static const char *mowa_dbchsz(cmd_parms *cmd, owa_context *octx,
                               char *charsize)
{
    int mxchsz;
    if (charsize)
    {
        mxchsz = str_atoi(charsize);
        if (mxchsz > 1)
        {
            if (mxchsz > 4) mxchsz = 4;
            octx->db_charsize = mxchsz;
        }
    }
    return((char *)0);
}

static const char *mowa_round(cmd_parms *cmd, owa_context *octx,
                              char *scale_round, char *arr_round)
{
    if (scale_round)
      if (*scale_round)
        octx->scale_round = (un_long)str_atoi(scale_round);

    if (arr_round)
      if (*arr_round)
        octx->arr_round = (un_long)str_atoi(arr_round);

    return((char *)0);
}

static const char *mowa_table(cmd_parms *cmd, owa_context *octx,
                              char *table_name, char *content_column)
{
    octx->doc_table = table_name;
    octx->doc_column = content_column;

    return((char *)0);
}

static const char *mowa_mem(cmd_parms *cmd, owa_context *octx, char *astr)
{
#ifndef NO_FILE_CACHE
    server_rec    *s;
    oracle_config *cfg;
    int            sz;

    /*
    ** The context passed in is for the "default" ("null") location.
    ** We don't really want to put this information there, because
    ** it won't be easily accessible to all locations.  Instead,
    ** put this on the module configuration.
    ** ### The Apache documentation doesn't promise that the server
    ** ### configuration will have been created yet, so this seems
    ** ### like it could fail.  Just in case, check it after retrieval,
    ** ### and exit if it doesn't appear valid.
    */
    s = cmd->server;
    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
      if (cfg->version != modowa_version)
        cfg = (oracle_config *)0;

    if ((cfg) && (astr))
    {
        sz = str_to_mem(astr);
        if (sz > 0)
        {
            cfg->mapmem->mapsize = sz;
            cfg->mapmem->memthresh = sz >> 4;
        }
    }
#endif

    return((char *)0);
}

static const char *mowa_thr(cmd_parms *cmd, owa_context *octx, char *astr)
{
    server_rec    *s;
    oracle_config *cfg;

    /*
    ** The context passed in is for the "default" ("null") location.
    ** We don't really want to put this information there, because
    ** it won't be easily accessible to all locations.  Instead,
    ** put this on the module configuration.
    ** ### The Apache documentation doesn't promise that the server
    ** ### configuration will have been created yet, so this seems
    ** ### like it could fail.  Just in case, check it after retrieval,
    ** ### and exit if it doesn't appear valid.
    */
    s = cmd->server;
    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
      if (cfg->version != modowa_version)
        cfg = (oracle_config *)0;

    if ((cfg) && (astr)) cfg->tinterval = str_to_tim(astr);

    return((char *)0);
}

/*
** Called once per location directive processed.  You can consider
** this to have been run once for all "worker" processes, though in
** fact on Unix the calls are done in the "template worker" and
** all the real worker processes inherit it through copy-on-write
** after being fork()ed.
*/
static void *oracle_location_config(apr_pool_t *p, char *dirspec)
{
    size_t       psize;
    size_t       asize;
    owa_context *octx;
#ifdef OWA_MULTI_THREADED
    int          threadmode = 0;
    int          maxthreads = 0;

    threadmode = 1;
#ifdef APACHE20
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threadmode);
    if (threadmode)
    {
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &maxthreads);
        if (maxthreads == 0) maxthreads = MAX_POOL;
    }
#else
    maxthreads = MAX_POOL;
#endif
#endif

    /*
    ** Allocate space in a single operation.
    **   owa_context structure
    **   owa_mt_context structure
    **   connection pool array
    **   string buffer for location
    */
    psize = sql_conn_size(MIN_POOL);
    asize = sizeof(*octx) + sizeof(owa_mt_context) + psize + 1;
    if (dirspec) asize += str_length(dirspec);
    octx = (owa_context *)apr_pcalloc(p, asize);
    /* ### NO WAY TO SIGNAL FAILURE ### */
    if (octx)
    {
        octx->mtctx = (owa_mt_context *)(void *)(octx + 1);
        octx->c_pool = (connection *)(void *)(octx->mtctx + 1);
        octx->location = ((char *)(void *)octx->c_pool) + psize;
        if (dirspec) str_copy(octx->location, dirspec);
#ifdef OWA_MULTI_THREADED
        octx->pool_wait_ms = MAX_WAIT;
#endif
        octx->dav_mode = 0;
        octx->poolsize = MIN_POOL;
        octx->version = OWA_AUTH_NONE;
        octx->nls_cs = (char *)"";
        octx->nls_lang = (char *)"";
        octx->nls_terr = (char *)"";
        octx->nls_tz = (char *)"";
        octx->nls_datfmt = (char *)"";
        octx->lobtypes = -1;
        octx->shm_offset = -1;
        octx->descmode = DESC_MODE_NORMAL;
        octx->verstring = modowa_version;
        octx->crtl_mask = (un_long)0xFFFFFFFF;
        octx->default_ctype = octx->error_ctype = "text/html";

#ifdef OWA_MULTI_THREADED
        /* Create the mutex which controls access to the connection pool */
        octx->multithread = maxthreads;
#ifdef APACHE20
        /*
        ** On Apache 2.0, this must be delayed until the worker is created.
        ** Except that an Apache mutex must have a pool to create from!
        */
        octx->mtctx->c_mutex = os_nullmutex;
#else
        octx->mtctx->c_mutex = ap_create_mutex((char *)0);
#endif
#else
        octx->mtctx->t_mutex = os_nullmutex;
#endif
#ifdef MODOWA_WINDOWS
        octx->keepalive_flag = OWA_KEEPALIVE_OK;
#endif
    }

    return((void *)octx);
}

/*
** This is called when Apache starts the "manager" process and again
** for the "template worker" process.  You can allocate memory here,
** but I/O connections aren't recommended because on Unix Apache
** will use fork() to create the "worker" processes, which will
** share any resources created here (memory is OK because the
** processes are copy-on-write).  On NT, this gets called twice
** in the startup/manager process, and once in the (multi-threaded)
** worker.  Unlike oracle_module (below), this seems to be called
** before any per-directory directives are processed by the module
** (though the documentation says you can't rely on that).  An example
** of something you might do here is load a configuration file into
** memory structures.  There is a server memory structure created
** here that is not specific to any directive.
*/
static void *oracle_server_config(apr_pool_t *p, server_rec *s)
{
    oracle_config *cfg;
    int            sz;

    sz = sizeof(oracle_config) + sizeof(shm_context);
#ifndef OWA_MULTI_THREADED
    /*
    ** For non-multi-threaded servers, global buffer that most of time
    ** is large enough for a SQL statement and the GET_PAGE array.
    */
    sz += HTBUF_ARRAY_SIZE * HTBUF_LINE_LENGTH;
#endif

    cfg = (oracle_config *)apr_pcalloc(p, sz);
    if (!cfg)
        alloc_failure(s, sz);
    else
    {
        cfg->version = modowa_version;
        cfg->thand = os_nullthrhand;
        cfg->o_mutex = os_nullmutex;
        cfg->mapmem = (shm_context *)(void *)(cfg + 1);
        cfg->mapmem->filthresh = CACHE_MAX_SIZE;
        cfg->mapmem->f_mutex = os_nullfilehand;
#ifndef OWA_MULTI_THREADED
        cfg->data_buffer = (char *)(void *)(cfg->mapmem + 1);
#endif
        RESET_ERRNO;
        ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                     "OWA server configured %d", os_get_pid());
    }

    return((void *)cfg);
}

#ifdef APACHE20
/*
** This is the manager process shutdown routine.  It's the place where
** resources global to all worker processes should be cleaned up.  In
** mod_owa's case the only such resources are the shared memory segment
** and its latch.
*/
static apr_status_t oracle_shutdown(void *data)
{
    server_rec    *s = (server_rec *)data;
    oracle_config *cfg;

    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
      if (cfg->version == modowa_version)
      {
          RESET_ERRNO;
          ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                       "Closing shared resources in PID %d", os_get_pid());
          if (!InvalidFile(cfg->mapmem->f_mutex))
              os_sem_destroy(cfg->mapmem->f_mutex);
#ifdef NO_MARK_FOR_DESTRUCT
          /* ### For Solaris, shared memory must be destroyed here ### */
          if (!InvalidFile(cfg->mapmem->map_fp))
              os_shm_destroy(cfg->mapmem->map_fp);
#endif
      }

    return((apr_status_t)0);
}
#endif

/*
** This is called whenever an Apache "worker" process exits.  It
** doesn't get called when the Apache "manager" process exits.  It
** is a good place to clean up resources used by workers.  It's
** called only once on the multi-threaded NT implementation.
*/
#ifdef APACHE20
static apr_status_t oracle_exit(void *data)
#else
static void oracle_exit(server_rec *s, pool *p)
#endif
{
#ifdef APACHE20
    server_rec    *s = (server_rec *)data;
#endif
    volatile oracle_config *cfg;
    owa_context   *octx;
    int            latch = 0;

    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);

    if (cfg)
      if (cfg->version == modowa_version)
      {
          if (!InvalidThread(cfg->thand)) thread_cancel(cfg->thand);

          if (InvalidMutex(cfg->o_mutex))
              latch = 1;
          else
              latch = os_mutex_acquire(cfg->o_mutex, SHMEM_WAIT_MAX);

          if (latch)
          {
            cfg->tinterval = 0; /* Trigger exit from cleanup thread */

            for (octx = cfg->loc_list; octx; octx = octx->next)
            {
              RESET_ERRNO;
              ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                           "Closing location %s", octx->location);
              owa_cleanup(octx);
              octx->init_complete = 0; /* To prevent further cleanup */
#ifndef OWA_MULTI_THREADED
              if (!InvalidMutex(octx->mtctx->t_mutex))
                  os_mutex_destroy(octx->mtctx->t_mutex);
#else
#ifdef APACHE20
              /* ### Not needed on Win32, so restricted to Apache 2.0 ### */
              if (!InvalidMutex(octx->mtctx->c_mutex))
                  os_mutex_destroy(octx->mtctx->c_mutex);
              if (!InvalidMutex(octx->mtctx->c_semaphore))
                  os_cond_destroy(octx->mtctx->c_semaphore);
#endif
#endif
            }
            cfg->loc_list = (owa_context *)0;

#ifndef NO_FILE_CACHE
            /* Detach shared memory and remove semaphore */
            if (cfg->mapmem->map_ptr)
            {
                os_shm_detach(cfg->mapmem->map_ptr);
                cfg->mapmem->map_ptr = (void *)0;
            }
#ifdef OWA_MULTI_THREADED
#ifndef APACHE20
            /*
            ** ### This works only for Win32 on Apache 1.3,
            ** ### because it's single-process.
            */
            if (!InvalidFile(cfg->mapmem->f_mutex))
                os_sem_destroy(cfg->mapmem->f_mutex);
            if (!InvalidFile(cfg->mapmem->map_fp))
                os_shm_destroy(cfg->mapmem->map_fp);
#endif
#endif
#endif
          }

          if (!InvalidThread(cfg->thand))
#ifdef MODOWA_WINDOWS
              thread_suspend(cfg->thand);
#else
              thread_cancel(cfg->thand);
#endif

          if (!InvalidMutex(cfg->o_mutex))
          {
            os_objptr m = cfg->o_mutex;
            cfg->o_mutex = os_nullmutex;
            RESET_ERRNO;
            ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                         "Destroy config mutex in PID %d", os_get_pid());
            os_mutex_release(m);
            os_mutex_destroy(m);
          }
      }
#ifdef APACHE20
#ifdef NEVER /* MODOWA_WINDOWS */
    /*
    ** ### TOTAL HACK: CALL oracle_shutdown BECAUSE WE FORCED APACHE TO
    ** ### CALL oracle_exit IN ITS PLACE ON WINDOWS TO WORK AROUND THE
    ** ### LACK OF PROPER SUPPORT FOR THE CHILD PROCESS EXIT HOOK
    */
    return(oracle_shutdown((void *)s));
#else
    return((apr_status_t)0);
#endif
#endif
}

#ifdef APACHE20
/*
** No-op function to satisfy requirement for child cleanup routine
*/
static apr_status_t oracle_nop(void *data)
{
    return((apr_status_t)0);
}
#endif

/*
** This is supposed to be called whenever the module is "loaded" by
** Apache.  It gets called twice on Unix, once in the "manager"
** process and again in the "template worker" process; it doesn't
** get called directly in any of the workers.  Apache seems to
** spawn one process from which all other workers are created by
** fork(); they appear to inherit whatever this routine does in
** the way of setup.  Because of this, this could be a good place
** to initialize some data structures, but it's a bad place to do
** things like open I/O connections (unless you plan to share
** them among all workers).  On NT, it gets called three times,
** twice in the Apache starter/manager process, and a third time
** by the (multi-threaded) worker process.
**
** Note that despite appearances, this function gets called after
** all of the Location directives have been processed!  This is
** despite the fact that LoadModule (if present) will appear
** first in httpd.conf, and the obvious fact that the module must
** already be loaded in order for the directives to work!
*/
#ifdef APACHE20
static int oracle_module(apr_pool_t *p, apr_pool_t *ptemp, 
                          apr_pool_t *plog, server_rec *s)
#else
static void oracle_module(server_rec *s, pool *p)
#endif
{
    oracle_config *cfg;
    int            sz = 0;

#ifdef APACHE20
    apr_pool_cleanup_register(p, (void *)s, oracle_shutdown, oracle_nop);
    ap_add_version_component(p, modowa_version);
#else
    ap_add_version_component(modowa_version);
#endif

#ifdef APACHE20
    {
      void *data = NULL;
      const char *datakey = "modowa_post_config";
      apr_pool_userdata_get(&data, datakey, s->process->pool);
      if (data == NULL)
      {
        apr_pool_userdata_set((const void *)datakey, datakey,
                              apr_pool_cleanup_null, s->process->pool);
        /* This is the first-time call */
        ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                     "OWA module first-time call for %d", os_get_pid());
        /* ### Possibly use this to force one-time init of shmem? ### */
      }
    }
#endif

    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);
    if (cfg)
      if (cfg->version == modowa_version)
      {
        sz = owa_shmem_init(cfg->mapmem);
        if (sz > 0)
        {
            RESET_ERRNO;
            ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                         "Created shared memory of %d bytes, PID %d",
                         sz, os_get_pid());
        }
      }

    RESET_ERRNO;
    ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                 "OWA module initialized %d", os_get_pid());
#ifdef APACHE20
    return(OK);
#endif
}

/*
** This is only called when a "worker" process is initialized.
** Since this process won't have any decendants, this should be
** the right place to create any I/O connections, etc.  On Unix,
** it's called in the worker right after it gets fork()ed.  On
** NT, you only get one call in the (multi-threaded) worker.  It
** doesn't ever seem to be called in the manager process.
*/
#ifdef APACHE20
static void oracle_init(apr_pool_t *p, server_rec *s)
#else
static void oracle_init(server_rec *s, pool *p)
#endif
{
    oracle_config *cfg;
    int            status;

#ifdef APACHE20
    apr_pool_cleanup_register(p, (void *)s, oracle_exit, oracle_nop);
#endif

    status = sql_init();

    cfg = (oracle_config *)ap_get_module_config(s->module_config, &owa_module);

    /* Create clean-up thread (if necessary) */
    if (cfg)
      if (cfg->version == modowa_version)
      {
        cfg->realpid = os_get_pid();
#ifndef OWA_MULTI_THREADED
        if (cfg->tinterval > 0)
#endif
        {
            /* Create mutex to control access to the config structure */
            cfg->o_mutex = os_mutex_create((char *)0, 1);
            RESET_ERRNO;
            if (InvalidMutex(cfg->o_mutex))
                cfg->tinterval = 0;
            else
                ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                             "Create config mutex in PID %d", cfg->realpid);
        }
        if (cfg->tinterval > 0)
        {
            cfg->thand = thread_spawn(oracle_thread, (void *)cfg, &(cfg->tid));
            if (InvalidThread(cfg->thand))
            {
                cfg->tinterval = 0;
                ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                             "Cleanup thread creation error in PID %d",
                             cfg->realpid);
            }
            else
            {
                RESET_ERRNO;
                ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                             "Cleanup thread %lx created in PID %d",
                             cfg->tid, cfg->realpid);
            }
        }
      }

    RESET_ERRNO;
    if (status == 0)
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, LOGSTATUS(s),
                     "Oracle OCI initialized %d", os_get_pid());
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, LOGSTATUS(s),
                     "Error %d initalizing OCI", status);
#ifdef NEVER
        os_exit(1); /* ### DON'T STOP APACHE FROM STARTING UP ### */
#endif
    }
}

#ifndef XtOffsetOf
#define XtOffsetOf(typ, fld) (((char *)(&(((typ *)0)->fld))) - ((char *)0))
#endif

#ifdef APACHE22
#define ARG_DFN       {(const char *(*)())ap_set_string_slot}
#define ARG_SET(loc)  ARG_DFN, (void *)XtOffsetOf(owa_context, loc)
#define ARG_FN(f)     {(const char *(*)())f}, (void *)0
#else
#define ARG_DFN       (const char *(*)())ap_set_string_slot
#define ARG_SET(loc)  ARG_DFN, (void *)XtOffsetOf(owa_context, loc)
#define ARG_FN(f)     (const char *(*)())f, (void *)0
#endif

#ifdef APACHE20
#define ARG_PATTERN(nm, st, cf, tk, hlp) {nm, st, cf, tk, hlp}

static const command_rec ora_commands[] =
{
ARG_PATTERN("OwaCache",        ARG_FN(mowa_cache),  ACCESS_CONF,  TAKE23,
            "OwaCache <logical name> <physical name> [lifespan]"       ),
ARG_PATTERN("OwaUserid",       ARG_FN(mowa_uid),    ACCESS_CONF,   TAKE1,
            "OwaUserid <username/password>[@dbname]"                   ),
ARG_PATTERN("OwaNLS",          ARG_FN(mowa_nls),    ACCESS_CONF,   TAKE1,
            "OwaNLS [language][_territory][.]<characterset>"           ),
ARG_PATTERN("OwaAuth",         ARG_FN(mowa_ver),    ACCESS_CONF,  TAKE12,
            "OwaAuth [OWA_INIT or OWA_CUSTOM] [PACKAGE]"               ),
ARG_PATTERN("OwaPool",         ARG_FN(mowa_pool),   ACCESS_CONF,   TAKE1,
            "OwaPool <poolsize, range 0-255, or THREADS>"              ),
ARG_PATTERN("OwaWait",         ARG_FN(mowa_wait),   ACCESS_CONF,  TAKE12,
            "OwaWait <milliseconds> [ABORT]"                           ),
ARG_PATTERN("OwaOptimizer",    ARG_SET(optimizer_mode),ACCESS_CONF,TAKE1,
            "OwaOptimizer <optimizer mode>"                            ),
ARG_PATTERN("OwaDiag",         ARG_FN(mowa_diag),   ACCESS_CONF, ITERATE,
            "OwaDiag [diagnostics]"                                    ),
ARG_PATTERN("OwaLog",          ARG_SET(diagfile),   ACCESS_CONF,   TAKE1,
            "OwaLog <filepath/name>"                                   ),
ARG_PATTERN("OwaDescribe",     ARG_FN(mowa_desc),   ACCESS_CONF,  TAKE12,
            "OwaDescribe <mode> [schema]"                              ),
ARG_PATTERN("OwaAlternate",    ARG_FN(mowa_alt),    ACCESS_CONF, ITERATE,
            "OwaAlternate <package name> [options]"                    ),
ARG_PATTERN("OwaUnicode",      ARG_FN(mowa_uni),    ACCESS_CONF,   TAKE1,
            "OwaUnicode <mode>"                                        ),
ARG_PATTERN("OwaReset",        ARG_FN(mowa_rset),   ACCESS_CONF,   TAKE1,
            "OwaReset <mode>"                                          ),
ARG_PATTERN("OwaStart",        ARG_SET(doc_start),  ACCESS_CONF,   TAKE1,
            "OwaStart <initial page procedure>"                        ),
ARG_PATTERN("OwaBefore",       ARG_SET(ora_before), ACCESS_CONF,   TAKE1,
            "OwaBefore <before procedure>"                             ),
ARG_PATTERN("OwaAfter",        ARG_SET(ora_after),  ACCESS_CONF,   TAKE1,
            "OwaAfter <after procedure>"                               ),
ARG_PATTERN("OwaProc",         ARG_SET(ora_proc),   ACCESS_CONF,   TAKE1,
            "OwaProc <page handling procedure>"                        ),
ARG_PATTERN("OwaLDAP",         ARG_SET(ora_ldap),   ACCESS_CONF,   TAKE1,
            "OwaLDAP <LDAP handling procedure>"                        ),
ARG_PATTERN("OwaCharsize",     ARG_FN(mowa_dbchsz), ACCESS_CONF,   TAKE1,
            "OwaCharsize <DB max char size>"                           ),
ARG_PATTERN("OwaAdmin",        ARG_FN(mowa_crtl),   ACCESS_CONF,   TAKE2,
            "OwaAdmin <IP subnet> <IP mask>"                           ),
ARG_PATTERN("OwaRound",        ARG_FN(mowa_round),  ACCESS_CONF,   TAKE2,
            "OwaRound <scalar> <array>"                                ),
ARG_PATTERN("OwaRealm",        ARG_SET(authrealm),  ACCESS_CONF,   TAKE1,
            "OwaRealm <admin realm>"                                   ),
ARG_PATTERN("OwaDav",          ARG_SET(dav_handler),ACCESS_CONF,   TAKE1,
            "OwaDav <package name>"                                    ),
ARG_PATTERN("OwaHttp",         ARG_FN(mowa_http),   ACCESS_CONF,   TAKE1,
            "OwaHttp <mode>"                                           ),
ARG_PATTERN("OwaFlex",         ARG_FN(mowa_flex),   ACCESS_CONF,   TAKE1,
            "OwaFlex <package/procedure name>"                         ),
ARG_PATTERN("OwaReject",       ARG_FN(mowa_reject), ACCESS_CONF,   TAKE1,
            "OwaReject <package/procedure prefix>"                     ),
ARG_PATTERN("OwaEnv",          ARG_FN(mowa_env),    ACCESS_CONF,   TAKE2,
            "OwaEnv <variable name> <variable value>"                  ),
ARG_PATTERN("OwaDocPath",      ARG_SET(doc_path),   ACCESS_CONF,   TAKE1,
            "OwaDocPath <virtual path for document download>"          ),
ARG_PATTERN("OwaDocProc",      ARG_SET(doc_proc),   ACCESS_CONF,   TAKE1,
            "OwaDocProc <document read procedure>"                     ),
ARG_PATTERN("OwaDocLong",      ARG_SET(doc_long),   ACCESS_CONF,   TAKE1,
            "OwaDocLong <virtual path for legacy documents>"           ),
ARG_PATTERN("OwaDocFile",      ARG_SET(doc_file),   ACCESS_CONF,   TAKE1,
            "OwaDocFile <virtual path for file-based documents>"       ),
ARG_PATTERN("OwaDocGen",       ARG_SET(doc_gen),    ACCESS_CONF,   TAKE1,
            "OwaDocGen <virtual path for generated documents>"         ),
ARG_PATTERN("OwaDocLobs",      ARG_FN(mowa_lobs),   ACCESS_CONF, ITERATE,
            "OwaDocLobs [supported LOB types] [Long length mode]"      ),
ARG_PATTERN("OwaDocTable",     ARG_FN(mowa_table),  ACCESS_CONF,   TAKE2,
            "OwaDocTable <table_name> <content_column>"                ),
ARG_PATTERN("OwaSqlError",     ARG_SET(sqlerr_uri), ACCESS_CONF,   TAKE1,
            "OwaSqlError <URL for showing SQL errors>"                 ),
ARG_PATTERN("OwaSession",      ARG_SET(session),    ACCESS_CONF,   TAKE1,
            "OwaSession <session cookie name>"                         ),
ARG_PATTERN("OwaUploadMax",    ARG_FN(mowa_upmx),   ACCESS_CONF,   TAKE1,
            "OwaUploadMax <maximum upload size>"                       ),
ARG_PATTERN("OwaCharset",      ARG_FN(mowa_dad),    ACCESS_CONF,   TAKE1,
            "OwaCharset <iso character set name>"                      ),
ARG_PATTERN("OwaBindset",      ARG_SET(defaultcs),  ACCESS_CONF,   TAKE1,
            "OwaBindset <oracle character set name>"                   ),
ARG_PATTERN("OwaTZ",           ARG_SET(nls_tz),     ACCESS_CONF,   TAKE1,
            "OwaTZ <time zone string>"                                 ),
ARG_PATTERN("OwaDateFmt",      ARG_SET(nls_datfmt), ACCESS_CONF,   TAKE1,
            "OwaDateFmt <date/time format string>"                     ),
ARG_PATTERN("OwaContentType",  ARG_FN(mowa_ctype),  ACCESS_CONF,  TAKE12,
            "OwaContentType <content type> [error content type]"),
/*
** These are the only module-level configuration directives:
*/
ARG_PATTERN("OwaSharedMemory", ARG_FN(mowa_mem),   RSRC_CONF,     TAKE1,
            "OwaSharedMemory <size>"                                  ),
ARG_PATTERN("OwaSharedThread", ARG_FN(mowa_thr),   RSRC_CONF,     TAKE1,
            "OwaSharedThread <interval>"                              ),
ARG_PATTERN("OwaFileRoot",     ARG_SET(froot),     RSRC_CONF,     TAKE1,
            "OwaFileRoot <directory path>"                            ),
{0}
};

#else

#define ARG_PATTERN(nm1, nm2, st, tk, hlp) \
 {nm1, st, ACCESS_CONF, tk, hlp}, {nm2, st, ACCESS_CONF, tk, hlp}

static const command_rec ora_commands[] =
{
ARG_PATTERN("oracle_cache",   "OwaCache",      ARG_FN(mowa_cache),      TAKE23,
            "oracle_cache <logical name> <physical name> [lifespan]"         ),
ARG_PATTERN("oracle_userid",  "OwaUserid",     ARG_FN(mowa_uid),         TAKE1,
            "oracle_userid <username/password>[@dbname]"                     ),
ARG_PATTERN("oracle_nls",     "OwaNLS",        ARG_FN(mowa_nls),         TAKE1,
            "oracle_nls [language][_territory][.]<characterset>"             ),
ARG_PATTERN("oracle_ver",     "OwaAuth",       ARG_FN(mowa_ver),        TAKE12,
            "oracle_ver [OWA_INIT or OWA_CUSTOM] [PACKAGE]"                  ),
ARG_PATTERN("oracle_pool",    "OwaPool",       ARG_FN(mowa_pool),        TAKE1,
            "oracle_pool <poolsize, range 0-255, or THREADS>"                ),
ARG_PATTERN("oracle_wait",    "OwaWait",       ARG_FN(mowa_wait),       TAKE12,
            "oracle_wait <milliseconds>"                                     ),
ARG_PATTERN("oracle_opt",     "OwaOptimizer",  ARG_SET(optimizer_mode),  TAKE1,
            "oracle_opt <optimizer mode>"                                    ),
ARG_PATTERN("oracle_diag",    "OwaDiag",       ARG_FN(mowa_diag),      ITERATE,
            "oracle_diag [diagnostics]"                                      ),
ARG_PATTERN("oracle_log",     "OwaLog",        ARG_SET(diagfile),        TAKE1,
            "oracle_log <filepath/name>"                                     ),
ARG_PATTERN("oracle_describe","OwaDescribe",   ARG_FN(mowa_desc),       TAKE12,
            "oracle_describe <mode> [schema]"                                ),
ARG_PATTERN("oracle_alt",     "OwaAlternate",  ARG_FN(mowa_alt),       ITERATE,
            "oracle_alt <package name> [options]"                            ),
ARG_PATTERN("oracle_uni",     "OwaUnicode",    ARG_FN(mowa_uni),         TAKE1,
            "oracle_uni <mode>"                                              ),
ARG_PATTERN("oracle_rset",    "OwaReset",      ARG_FN(mowa_rset),        TAKE1,
            "oracle_rset <mode>"                                             ),
ARG_PATTERN("oracle_start",   "OwaStart",      ARG_SET(doc_start),       TAKE1,
            "oracle_start <initial page procedure>"                          ),
ARG_PATTERN("oracle_before",  "OwaBefore",     ARG_SET(ora_before),      TAKE1,
            "oracle_before <before procedure>"                               ),
ARG_PATTERN("oracle_after",   "OwaAfter",      ARG_SET(ora_after),       TAKE1,
            "oracle_after <after procedure>"                                 ),
ARG_PATTERN("oracle_proc",    "OwaProc",       ARG_SET(ora_proc),        TAKE1,
            "oracle_proc <page handling procedure>"                          ),
ARG_PATTERN("oracle_ldap",    "OwaLDAP",       ARG_SET(ora_ldap),        TAKE1,
            "oracle_ldap <LDAP handling procedure>"                          ),
ARG_PATTERN("oracle_charsize","OwaCharsize",   ARG_FN(mowa_dbchsz),      TAKE1,
            "oracle_charsize <DB max char size>"                             ),
ARG_PATTERN("oracle_admin",   "OwaAdmin",      ARG_FN(mowa_crtl),        TAKE2,
            "oracle_admin <IP subnet> <IP mask>"                             ),
ARG_PATTERN("oracle_round",   "OwaRound",      ARG_FN(mowa_round),       TAKE2,
            "oracle_round <scalar> <array>"                                  ),
ARG_PATTERN("oracle_realm",   "OwaRealm",      ARG_SET(authrealm),       TAKE1,
            "oracle_realm <admin realm>"                                     ),
ARG_PATTERN("oracle_dav",     "OwaDav",        ARG_SET(dav_handler),     TAKE1,
            "oracle_dav <package name>"                                      ),
ARG_PATTERN("oracle_http",    "OwaHttp",       ARG_FN(mowa_http),        TAKE1,
            "oracle_http <mode>"                                             ),
ARG_PATTERN("oracle_flex",    "OwaFlex",       ARG_FN(mowa_flex),        TAKE1,
            "oracle_flex <package/procedure name>"                           ),
ARG_PATTERN("oracle_reject",  "OwaReject",     ARG_FN(mowa_reject),      TAKE1,
            "oracle_reject <package/procedure prefix>"                       ),
ARG_PATTERN("oracle_env",     "OwaEnv",        ARG_FN(mowa_env),         TAKE2,
            "oracle_env <variable name> <variable value>"                    ),
ARG_PATTERN("document_path",  "OwaDocPath",    ARG_SET(doc_path),        TAKE1,
            "document_path <virtual path for document download>"             ),
ARG_PATTERN("document_proc",  "OwaDocProc",    ARG_SET(doc_proc),        TAKE1,
            "document_proc <document read procedure>"                        ),
ARG_PATTERN("document_long",  "OwaDocLong",    ARG_SET(doc_long),        TAKE1,
            "document_long <virtual path for legacy documents>"              ),
ARG_PATTERN("document_file",  "OwaDocLong",    ARG_SET(doc_file),        TAKE1,
            "document_file <virtual path for file-based documents>"          ),
ARG_PATTERN("document_gen",   "OwaDocGen",     ARG_SET(doc_gen),         TAKE1,
            "document_gen <virtual path for generated documents>"            ),
ARG_PATTERN("oracle_error",   "OwaSqlError",   ARG_SET(sqlerr_uri),      TAKE1,
            "oracle_error <URL for showing SQL errors>"                      ),
ARG_PATTERN("oracle_ses",     "OwaSession",    ARG_SET(session),         TAKE1,
            "oracle_ses <session cookie name>"                               ),
ARG_PATTERN("document_lobs",  "OwaDocLobs",    ARG_FN(mowa_lobs),      ITERATE,
            "document_lobs [supported LOB types] [Long length mode]"         ),
ARG_PATTERN("document_table", "OwaDocTable",   ARG_FN(mowa_table),       TAKE2,
            "document_table <table_name> <content_column>"                   ),
ARG_PATTERN("upload_max",     "OwaUploadMax",  ARG_FN(mowa_upmx),        TAKE1,
            "upload_max <maximum upload size>"                               ),
ARG_PATTERN("dad_charset",    "OwaCharset",    ARG_FN(mowa_dad),         TAKE1,
            "dad_charset <iso character set name>"                           ),
ARG_PATTERN("dad_bindset",    "OwaBindset",    ARG_SET(defaultcs),       TAKE1,
            "dad_bindset <oracle character set name>"                        ),
ARG_PATTERN("dad_tz",         "OwaTZ",         ARG_SET(nls_tz),          TAKE1,
            "dad_tz <time zone string>"                                      ),
ARG_PATTERN("dad_datefmt",    "OwaDateFmt",    ARG_SET(nls_datfmt),      TAKE1,
            "dad_datefmt <date/time format string>"                          ),
ARG_PATTERN("oracle_ctype",   "OwaContentType",ARG_FN(mowa_ctype),      TAKE12,
            "oracle_ctype <content type> [error content type]"               ),
/*
** These are the only module-level configuration directives:
*/
{"OwaFileRoot",       ARG_SET(froot),   RSRC_CONF, TAKE1,
 "OwaFileRoot <directory path>"},
{"OwaSharedMemory",   ARG_FN(mowa_mem), RSRC_CONF, TAKE1,
 "OwaSharedMemory <size>"},
{"OwaSharedThread",   ARG_FN(mowa_thr), RSRC_CONF, TAKE1,
 "OwaSharedThread <interval>"},
{"owa_shared_memory", ARG_FN(mowa_mem), RSRC_CONF, TAKE1,
 "owa_shared_memory <size>"},
{"owa_shared_thread", ARG_FN(mowa_thr), RSRC_CONF, TAKE1,
 "owa_shared_thread <interval>"},
{0}
};

#endif /* APACHE 1.3 */

#ifndef APACHE20

static const handler_rec ora_handlers[] =
{
    {"owa_handler", mowa_handler},
    {0}
};

MODULE_VAR_EXPORT module owa_module =
{
    MODULE_MAGIC_NUMBER_MAJOR,
    MODULE_MAGIC_NUMBER_MINOR,
    -1,
    "modowa.c",
    NULL,
    NULL,
#ifdef USE_OLD_MAGIC
    MODULE_MAGIC_COOKIE_AP13,
#else
    MODULE_MAGIC_COOKIE,
#endif
    oracle_module,                  /* module initializer */
    oracle_location_config,         /* dir config creator */
    NULL,                           /* dir merger - default is to override */
    oracle_server_config,           /* server config */
    NULL,                           /* merge server config */
    ora_commands,                   /* command table */
    ora_handlers,                   /* handlers */
    NULL,                           /* filename translation */
    NULL,                           /* check_user_id */
    NULL,                           /* check auth */
    NULL,                           /* check access */
    NULL,                           /* type_checker */
    NULL,                           /* fixups */
    NULL,                           /* logger */
    NULL,                           /* header parser */
    oracle_init,                    /* child initializer */
    oracle_exit,                    /* child cleanup */
    NULL                            /* post read_request handling */
#ifdef EAPI
    ,NULL                           /* add module */
    ,NULL                           /* remove module */
    ,NULL                           /* rewrite command */
    ,NULL                           /* new connection */
    ,NULL                           /* close connection */
#endif
};
/* ### HOW TO ENSURE BLANK PADDING IF NOT COMPILED WITH EAPI? ### */

#else /* APACHE20 */

static void ora_hooks(apr_pool_t *p)
{
    ap_hook_handler(mowa_handler, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_post_config(oracle_module,
                        NULL, /* Predecessors */
                        NULL, /* Successors */
                        APR_HOOK_MIDDLE); /* FIRST/MIDDLE/LAST */
    ap_hook_child_init(oracle_init,
                       NULL, /* Predecessors */
                       NULL, /* Successors */
                       APR_HOOK_MIDDLE);
}

AP_MODULE_DECLARE_DATA module owa_module =
{
    STANDARD20_MODULE_STUFF,
    oracle_location_config,         /* dir config creator */
    NULL,                           /* dir merger --- default is to override */
    oracle_server_config,           /* server config */
    NULL,                           /* merge server config */
    ora_commands,                   /* command table */
    ora_hooks
};

#endif /* APACHE20 */
