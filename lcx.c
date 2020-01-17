#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

//#undef WIN32

#define XSOCK_VERSION "1.0.0"
#define DEFAULT_PROXY_PORT 1080
#define CC_PORT 12345
#define CC_CTL_PORT 54321

#define BUF_LEN 8192

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif



#ifdef WIN32
//
// WIN32 COMPILE
//
#define WIN32_LEAN_AND_MEAN
#include<winsock2.h>
#include<windows.h>
#include <process.h>
#pragma comment(lib, "Ws2_32")

#define SOCKET_INIT {WSADATA wsa;WSAStartup(MAKEWORD(2,2),&wsa);}
#define SOCKET_UNINIT {WSACleanup();}

typedef int socklen_t;

#define delay(x) Sleep(x)

// #define PTHREAD_INIT {pthread_win32_process_attach_np();pthread_win32_thread_attach_np();atexit(detach_ptw32);}
//
// static void detach_ptw32(void)
// {
// pthread_win32_thread_detach_np();
// pthread_win32_process_detach_np();
// }

#define xstrnicmp strnicmp

#pragma warning(disable: 4214)

#else
//
// LINUX COMPILE
//
#include <unistd.h>

#define PTW32_STATIC_LIB


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <pthread.h>
#include <execinfo.h>
#include <signal.h>

#define PTHREAD_INIT
#define SOCKET_INIT
#define SOCKET_UNINIT

typedef int SOCKET;

#define delay(x) usleep(x*1000)
#define closesocket(x) close(x)
#define xstrnicmp strncasecmp

int b_sigsegv = 0;
void get_stack()
{
	int i;
	void *buffer[1024];
	int n = backtrace(buffer, 1024);
	char **symbols = backtrace_symbols(buffer, n);

	for (i = 0; i < n; i++)
	{
		printf("%s\n", symbols[i]);
	}
}

void sig_handler(int s)
{
	if (s == SIGSEGV)
	{
		if (b_sigsegv == 0)
		{
			b_sigsegv = 1;
			get_stack();
		}
	}

	exit(1);
}


// typedef struct _thread_signal
// {
//     bool  relative;
//     pthread_cond_t cond;
//     pthread_mutex_t mutex;
//     pthread_condattr_t cattr;
// } thread_signal_t;
// 
// void thread_init_signal(thread_signal_t *signal, bool b_relative)
// {
//     signal->relative = b_relative;
//     pthread_mutex_init(&signal->mutex, NULL);
// 
//     if (b_relative)
//     {
//         int ret = pthread_condattr_init(&signal->cattr);
//         ret = pthread_condattr_setclock(&signal->cattr, CLOCK_MONOTONIC);
//         ret = pthread_cond_init(&signal->cond, &signal->cattr);
//     }
//     else
//     {
//         pthread_cond_init(&signal->cond, NULL);
//     }
// }
// 
// void thread_uninit_signal(thread_signal_t *signal)
// {
//     if (signal->relative)
//     {
//         pthread_condattr_destroy(&(signal->cattr));
//     }
// 
//     pthread_mutex_destroy(&signal->mutex);
//     pthread_cond_destroy(&signal->cond);
// }
// 
// int thread_wait_signal(thread_signal_t *signal, int ms);
// {
//     int ret = 0;
// 
//     pthread_mutex_lock(&signal->mutex);
//     if (signal->relative)
//     {
//         struct timespec outtime;
//         clock_gettime(CLOCK_MONOTONIC, &outtime);
//         outtime.tv_sec += ms/1000;
//         uint64_t us = outtime.tv_nsec/1000 + 1000 * (ms % 1000);
//         outtime.tv_sec += us / 1000000;
//         us = us % 1000000;
//         outtime.tv_nsec = us * 1000;
//         ret = pthread_cond_timedwait(&signal->cond, &signal->mutex, &outtime);
//     }
//     else
//     {
//         struct timeval now;
//         gettimeofday(&now, NULL);
//         struct timespec outtime;
//         outtime.tv_sec = now.tv_sec + ms / 1000;
//         uint64_t  us = now.tv_usec + 1000 * (ms % 1000);
//         outtime.tv_sec += us / 1000000;
//         us = us % 1000000;
//         outtime.tv_nsec = us * 1000;
// 
//         ret = pthread_cond_timedwait(&signal->cond, &signal->mutex, &outtime);
//     }
//     pthread_mutex_unlock(&signal->mutex);
// 
//     return ret;
// }
// 
// void thread_set_signal(ThreadSignal *signal)
// {
//     pthread_mutex_lock(&signal->mutex);
//     pthread_cond_signal(&signal->cond);
//     pthread_mutex_unlock(&signal->mutex);
// }


#endif


#ifdef WIN32
typedef unsigned __int8 uint8_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

#define xspf sprintf_s
#else

#include <stdint.h>

#define xspf snprintf
#define INVALID_SOCKET  (SOCKET)(~0)

#endif

//
// lock function
//
#ifdef WIN32

CRITICAL_SECTION cs;
int init_mutex()
{
	InitializeCriticalSection(&cs);
	printf("Init mutex\n");
	return 0;
}

int lock_mutex()
{
	//printf("wait for enter\n");
	EnterCriticalSection(&cs);
	//printf("enter mutex\n");
	return 0;
}

int unlock_mutex()
{
	//printf("wait for leave\n");
	LeaveCriticalSection(&cs);
	//printf("leave mutex\n");

	return 0;
}

int uninit_mutex()
{
	printf("delete mutex\n");
	DeleteCriticalSection(&cs);
	return 0;
}

#else

pthread_mutex_t mutex;

int init_mutex()
{
	pthread_mutex_init(&mutex, NULL);
	printf("Init mutex\n");

	return 0;
}

int lock_mutex()
{
	//printf("wait for enter\n");
	pthread_mutex_lock(&mutex);
	//printf("enter mutex\n");
	return 0;
}

int unlock_mutex()
{
	//printf("wait for leave\n");
	pthread_mutex_unlock(&mutex);
	//printf("leave mutex\n");

	return 0;
}

int uninit_mutex()
{
	pthread_mutex_destroy(&mutex);
	return 0;
}

#endif

//
// thread function
//
#ifdef	WIN32

typedef unsigned int (WINAPI *thread_fun_t)(void*);
#define THREAD_RETURN unsigned int WINAPI

#else

#define THREAD_RETURN void*
typedef void* (*thread_fun_t)(void*);

#endif

unsigned int get_thread_id();
int in_create_thread(thread_fun_t run, void* ctx, int b_wait);

unsigned int get_thread_id()
{
#ifdef	WIN32
	return GetCurrentThreadId();
#else
	return pthread_self();
#endif
}

int in_create_thread(thread_fun_t run, void* ctx, int b_wait)
{
#ifdef WIN32
    HANDLE h = (HANDLE)_beginthreadex(NULL, 0, run, ctx, 0, NULL);
	if (b_wait == 1)
	{
		if (h != NULL)
		{
			WaitForSingleObject(h, INFINITE);
		}
	}
    CloseHandle(h);
#else
    PTHREAD_INIT
    pthread_t t;
    pthread_create(&t, NULL, run, ctx);
#endif

    delay(300);
    return 0;
}

#if 0
typedef enum {
    SIMPLE_MODE = 0,
    SERVER_MODE,
    ClIENT_MODE,
    RELAY_MODE,
} work_mode_t;

typedef struct _work_cfg {
    uint16_t version;
    uint8_t level;
    uint8_t mode;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} work_cfg_t;

typedef struct _fwd_proto_hdr {
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t req;
} fwd_proto_hdr_t;
#endif

//
// log functions
//
FILE* portfwd_log = NULL;
FILE* portfwd_hex = NULL;
FILE* portfwd_text = NULL;

typedef enum {
    D_DBG = 0,
    D_INFO,
    D_WARN,
    D_ERR,
} log_level_t;

unsigned int g_log_level = D_DBG;
int log_file(char* out, unsigned int level, unsigned int mode);

int log_file(char* out, unsigned int level, unsigned int mode)
{
    int ret = 0;

	if (level >= g_log_level)
	{
		if (level == D_ERR)
		{
#ifdef WIN32
			printf("%s, err=%d", out, GetLastError());
#else
			printf("%s, err=%d", out, errno);
#endif
		}
		else
		{
			printf("%s", out);
		}
	}

	if (mode == 0xff)
	{
		return ret;
	}
	return ret;
#if 0
    if(portfwd_log)fprintf(portfwd_log,"%s",out),fflush(portfwd_log);
    if(portfwd_text)
    {
		char buf[1024];
		int len = strlen(out);
        fprintf(portfwd_text,"\n%s\n",out);
        fwrite(buf,1,len,portfwd_text);
        fflush(portfwd_text);
    }

    if(portfwd_hex)
    {
		int i;
		int len = strlen(out);
        fprintf(portfwd_hex,"\n%s",out);
        
        for(i=0; i<len; ++i)
        {
            if(i%16==0)fprintf(portfwd_hex,"\n");
            fprintf(portfwd_hex,"%02X ",buf[i]);
        }
        fflush(portfwd_hex);
    }

    return ret;
#endif
}

//
// cc fwd def
//
enum {
	LISTEN_MODE = 0,
	CC_MODE,
	TRAN_MODE,
	SLAVE_MODE,
	ADV_SLAVE_MODE,
	PROXY_MODE,
	CTL_MODE,
};


enum _fwd_cmd
{
	HEART_BEAT = 0,
	START_SLAVE,
	START_SLAVE_FIN,
	STOP_SLAVE,
	STOP_SLAVE_FIN,
	STOP_ALL,
	STOP_ALL_FIN
};

typedef struct _thread_slave_ctx
{
	char srv_ip[32];
	char tgt_ip[32];
	uint16_t srv_port;
	uint16_t tgt_port;
	uint32_t index;
} thread_slave_ctx_t;

typedef struct _cc_proto
{
	uint8_t ver;
	uint16_t flag;
	uint8_t b_stop:1,
	b_exit:1,
	b_new:1,
	b_ret:1,
	cmd:4;
	thread_slave_ctx_t ctx; //data
} cc_proto_t;

typedef struct _cc_proto_slave
{
	uint8_t ver;
	uint16_t flag;
	uint8_t b_stop:1,
	b_exit:1,
	b_new:1,
	b_ret:1,
	cmd:4;
	thread_slave_ctx_t ctx; //data
} cc_proto_slave_t;

typedef struct _thrd_cc_ctx {
	uint32_t tid;
	uint32_t index;
	uint32_t flag:1,
			 unused:1;
	SOCKET sock;
	uint16_t port; // listen
	uint16_t conn_port;
	uint32_t ipv4;
} thrd_cc_ctx_t;

thrd_cc_ctx_t g_table[32];

uint16_t g_server_port;

typedef struct _global_cc_cfg
{
	uint8_t b_stop:1,
	b_exit:1,
	b_new:1,
	b_ret:1,
	cmd:4;

	char srv_ip[32];
	char tgt_ip[32];
	uint16_t srv_port;
	uint16_t tgt_port;

} global_cc_cfg;

global_cc_cfg g_cc_cfg;

int total_connect = 0;

int cc_add_tgt(thrd_cc_ctx_t *ctx)
{
	int i;
	int b_find = 0;
	int b_add = 0;

	for (i = 0; i < 32; i++)
	{
		if (ctx->ipv4 == g_table[i].ipv4)
		{
			b_find = 1;
			break;
		}
	}

	if (b_find)
	{
		if (ctx->conn_port == g_table[i].conn_port)
		{
			return 1;
		}
		else
		{
			printf("cc new tgt port %d(%d) sock %d\n",
				ctx->conn_port, g_table[i].conn_port, ctx->sock);
			g_table[i].conn_port = ctx->conn_port;
			g_table[i].sock = ctx->sock;
		}
	}
	else
	{
		printf("cc new tgt %0x:%d sock %d\n",
			ctx->ipv4, ctx->conn_port, ctx->sock);

		for (i = 0; i < 32; i++)
		{
			if (g_table[i].ipv4 == 0 && g_table[i].conn_port == 0)
			{
				memcpy(&g_table[i], ctx, sizeof(thrd_cc_ctx_t));
				ctx->index = i;
				printf("cc add tgt [%d] %x:%d\n",
					i, g_table[i].ipv4, g_table[i].conn_port);
				b_add = 1;
				break;
			}
		}

		if (b_add == 0)
		{
			printf("cc tgt no space");
			return -1;
		}
	}

	return 0;
}

int cc_del_tgt(uint32_t ipv4, uint16_t conn_port)
{
	int i;

	for (i = 0; i < 32; i++)
	{
		if (g_table[i].ipv4 == ipv4 && g_table[i].conn_port == conn_port)
		{
			memset(&g_table[i], 0, sizeof(thrd_cc_ctx_t));
		}
	}

	return 0;
}

int cc_find_tgt(uint32_t ipv4, uint16_t conn_port, SOCKET *s)
{
	int i;
	for (i = 0; i < 32; i++)
	{
		if (g_table[i].ipv4 == ipv4 && g_table[i].conn_port == conn_port)
		{
			*s = g_table[i].sock; 
			printf("find [%d] %x:%d.\n",
				i, g_table[i].ipv4, g_table[i].conn_port);
			return i;
		}
	}

	return -1;
}

// cc function
int cc_client_work(cc_proto_t *p, SOCKET sock);
int cc_server_work(cc_proto_t *p, thrd_cc_ctx_t *ctx, int len);
int cc_ctl_work(cc_proto_t *p, int len, thrd_cc_ctx_t *ctx);




/* Set TCP keep alive option to detect dead peers. The interval option
 * is only used for Linux as we are using Linux-specific APIs to set
 * the probe send time, interval, and count. */
int set_sock_keepalive(SOCKET fd, int interval)
{
    int val = 3;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, sizeof(val)) == -1)
    {
        printf("setsockopt SO_KEEPALIVE: %d", errno);
        return -1;
    }

#ifndef WIN32

    /* Default settings are more or less garbage, with the keepalive time
     * set to 7200 by default on Linux. Modify settings to make the feature
     * actually useful. */

    /* Send first probe after interval. */
    val = interval;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
        printf("setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
        return -1;
    }

    /* Send next probes after the specified interval. Note that we set the
     * delay as interval / 3, as we send three probes before detecting
     * an error (see the next setsockopt call). */
    val = interval/3;
    if (val == 0) val = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
        printf("setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return -1;
    }

    /* Consider the socket in error state after three we send three ACK
     * probes without getting a reply. */
    val = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
        printf("setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return -1;
    }
#endif

    return 0;
}

THREAD_RETURN data_tran_thread(void* p)
{
    char out[100];
	int ret = 0;
    SOCKET t[2];
	socklen_t len;

    struct sockaddr_in sa[2];
    const unsigned char* ip[2];
    uint16_t port[2];

	fd_set fd_list,check_list;

	char buf[BUF_LEN];
	int OK = 1;
	int total_byte = 0;

    len = sizeof(struct sockaddr_in);
	t[0]=((int*)p)[0];
	t[1]=((int*)p)[1];

	set_sock_keepalive(t[0], 100);
	set_sock_keepalive(t[1], 100);

    if(getpeername(t[0],(struct sockaddr*)sa,&len) == -1 ||
            getpeername(t[1],(struct sockaddr*)(sa+1),&len) == -1)
    {
        log_file("[-] Get Remote Host Failed\n", D_ERR, 0xff);
        closesocket(t[0]);
        closesocket(t[1]);
        return 0;
    }

    ip[0] = (unsigned char*)&sa[0].sin_addr.s_addr;
    ip[1] = (unsigned char*)&sa[1].sin_addr.s_addr;
    port[0] = htons(sa[0].sin_port);
    port[1] = htons(sa[1].sin_port);

    FD_ZERO(&fd_list);
    FD_SET(t[0],&fd_list);
    FD_SET(t[1],&fd_list);

    ++total_connect;
    while( OK && ( (check_list = fd_list),(select(FD_SETSIZE,&check_list,NULL,NULL,NULL)>0)) )
    {
        int i;
		ret = -1;
        for(i = 0; i < 2; ++i)
        {
            if( FD_ISSET(t[i], &check_list) )
            {
                int len = recv(t[i], buf, BUF_LEN, 0);
                if(len > 0)
                {
					if (send(t[i==0], buf, len, 0) > 0)
					{
						ret = 0;
					}
                }

				if(ret == -1)
                {
                    OK = 0;
                    if (g_log_level)
                    {
                        xspf(out, sizeof(out),
                                 "[+]  Connection <Total %d> Cutdown, Total : %d Bytes\n\n",
                                 total_connect, total_byte);
                        log_file(out, D_INFO, 0xff);
                    }
                    break;
                }
				else
				{
					total_byte += len;
					if (g_log_level)
					{
						xspf(out, sizeof(out),
							"[+]  Send <Total %d>: %d.%d.%d.%d:%d->%d.%d.%d.%d:%d,%dB\n",
							total_connect,
							ip[i][0], ip[i][1], ip[i][2], ip[i][3], port[i],
							ip[i==0][0], ip[i==0][1], ip[i==0][2], ip[i==0][3],
							port[i==0], len);
						log_file(out, D_INFO, 0xff);
					}
				}
            }
        }
    }
    --total_connect;

    closesocket(t[0]);
    closesocket(t[1]);

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

unsigned long fwd_get_host(const char* name)
{
    char out[100];

    if(name)
    {
        struct hostent *host = gethostbyname(name);
        unsigned long i;
        if(host && host->h_addr)
        {
            i = *(long *)(host->h_addr);
            return i;
        }
    }

#ifdef WIN32
    xspf(out, sizeof(out),
		"\nERROR: %s: Wrong host address%d\n", name, GetLastError());
#else
	xspf(out, sizeof(out),
		"\nERROR: %s: Wrong host address%d\n", name, errno);
#endif
    log_file(out, D_ERR, 0xff);

    return 0;
}


int fwd_slave(char* srv_ip, uint16_t port1, char* tgt_ip, uint16_t port2)
{
    int ret = -1;
    char out[100];
    char out1[100], out2[100];
	unsigned int tms = 0;

    while(1)
    {
		SOCKET s[2];
        unsigned char *ip[2];
        unsigned long ip1, ip2;
        struct sockaddr_in sa[2];

		ip1 = fwd_get_host(srv_ip);
        if(-1 == ip1)
        {
            xspf(out, sizeof(out),
                     "[-]  Reslove Host %s Failed...\n", srv_ip);
            log_file(out, D_ERR, 0xff);
            break;
        }

        ip2 = fwd_get_host(tgt_ip);
        if(-1 == ip2)
        {
            xspf(out, sizeof(out),
                     "[-]  Reslove Host %s Failed...\n", tgt_ip);
            log_file(out, D_ERR, 0xff);
            break;
        }

        ip[0] = (unsigned char*)&ip1;
        ip[1] = (unsigned char*)&ip2;
        xspf(out1, sizeof(out1), "%d.%d.%d.%d:%d",
			ip[0][0],ip[0][1],ip[0][2],ip[0][3],port1);
        xspf(out2, sizeof(out2), "%d.%d.%d.%d:%d",
			ip[1][0],ip[1][1],ip[1][2],ip[1][3],port2);
        
        s[0] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        s[1] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

        sa[0].sin_family = AF_INET;
        sa[0].sin_port = htons(port1);
        sa[0].sin_addr.s_addr = (ip1);
        sa[1].sin_family = AF_INET;
        sa[1].sin_port = htons(port2);
        sa[1].sin_addr.s_addr = (ip2);

        if(s[0]!=-1 && s[1]!=-1)
        {
			char c;

            if (g_log_level)
            {
                xspf(out, sizeof(out), "[+]  Connect %s, Please Wait\n",out1);
                log_file(out, D_INFO, 0xff);
            }

            while(connect(s[0],(struct sockaddr*)&sa[0],sizeof(struct sockaddr))!=0)
            {
                if (g_log_level)
                {
                    xspf(out, sizeof(out), "[-]  Connect %s Failed,Try Again..\n",out1);
                    log_file(out, D_INFO, 0xff);
                }

                if (tms > 3)
                {
                    //printf("wait...\n");
                    tms = 0;
                    closesocket(s[0]);
                    closesocket(s[1]);
                    return ret;
                }
                delay(1000);
                tms++;
            }

			set_sock_keepalive(s[0], 100);
            if(recv(s[0],(char*)&c,1,MSG_PEEK)<=0)
            {
                if (g_log_level)
                {
                    xspf(out, sizeof(out), "[-]  Connect %s Failed,CutDown...\n", out2);
                    log_file(out, D_INFO, 0xff);
                }
                closesocket(s[0]);
                closesocket(s[1]);
                continue;
            }

            // after recv data connect target
            if (g_log_level)
            {
                xspf(out, sizeof(out), "[+]  Connect %s Successed,Now Connect %s\n",
                         out1, out2);
                log_file(out, D_INFO, 0xff);
            }

            if(connect(s[1],(struct sockaddr*)&sa[1],sizeof(struct sockaddr))==0)
            {
                if (g_log_level)
                {
                    xspf(out, sizeof(out), "[+]  Connect %s Successed,Transfering...\n", out2);
                    log_file(out, D_INFO, 0xff);
                }
                ret = in_create_thread(data_tran_thread, s, 0);
            }
            else
            {
                if (g_log_level)
                {
                    xspf(out, sizeof(out), "[-]  Connect %s Failed,CutDown...\n", out2);
                    log_file(out, D_ERR, 0xff);
                }

                closesocket(s[0]);
                closesocket(s[1]);
            }
        }
        else
        {
            log_file("[-]  Create Socket Failed\n", D_ERR, 0xff);
            return ret;
        }
        delay(1000);
    }

    return ret;
}

int fwd_listen(uint16_t port1,uint16_t port2, uint32_t flag)
{
    SOCKET s[2];
    uint16_t p[2];
    struct sockaddr_in sa;
    int i;
    int OK = 0;
	SOCKET t[2];
	socklen_t sz;

	p[0]=port1;
	p[1]=port2;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;

	printf("fwd_listen in mode %d\n", flag);
    for(i=0; i<2; ++i)
    {
        s[i] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s[i]!=-1)
        {
            fprintf(stdout,"[+]  Create Socket %d Successed\n",i+1);
            fflush(stdout);
            sa.sin_port = htons(p[i]);
            if(bind(s[i],(struct sockaddr*)&sa,sizeof(sa))==0)
            {
                fprintf(stdout,"[+]  Bind On Port %u Success\n",p[i]);
                fflush(stdout);
                if(listen(s[i],SOMAXCONN)==0)
                {
                    fprintf(stdout,"[+]  Listen On Port %u Successed\n",p[i]);
                    fflush(stdout);
                    OK =  1;
                }
                else
                {
                    fprintf(stdout,"[-]  Listen On Port %u Failed\n",p[i]);
                    break;
                }
            }
            else
            {
                fprintf(stdout,"[-]  Bind On Port %u Failed\n",p[i]);
                break;
            }
        }
        else
        {
            fprintf(stdout,"[-]  Create Socket %d Failed\n",i+1);
            break;
        }
    }

    if(!OK)
    {
        closesocket(s[0]);
        closesocket(s[1]);
        return -1;
    }

    i = 0;
	sz = sizeof(sa);
    while(1)
    {
		unsigned char *ip;
        fprintf(stdout,"[+]  Waiting Connect On Port %u\n",p[i]);
        fflush(stdout);
        t[i] = accept(s[i],(struct sockaddr*)&sa,&sz);
        ip = (unsigned char*)&sa.sin_addr.s_addr;
        if(t[i] != -1)
        {
            fprintf(stdout,"[+]  Connect From %d.%d.%d.%d:%d On Port %d\n",
				ip[0],ip[1],ip[2],ip[3],htons(sa.sin_port),p[i]);
            fflush(stdout);
            if(i == 1)
            {
                in_create_thread(data_tran_thread, t, 0);
            }
            i = (i == 0);
        }
        else
        {
            fprintf(stdout,"[-]  Accept Failed On Port %d\n",p[i]);
            i=0;
        }
    }

	closesocket(s[0]);
	closesocket(s[1]);

    return 0;
}

THREAD_RETURN thread_cc_work(void *para)
{
	int ret = 0;
	SOCKET new_sock;
	char buf[BUF_LEN];
	thrd_cc_ctx_t ctx;

	memcpy(&ctx, para, sizeof(thrd_cc_ctx_t));
	ctx.tid = get_thread_id();
	printf("thread_cc_work(%0x) mode(%d) enter.\n", ctx.tid, ctx.flag);

	new_sock = ctx.sock;
	//set_recv_timeout(new_sock, 10);
	while (g_cc_cfg.b_exit == 0 && g_cc_cfg.b_stop == 0)
	{
		int len = 0;
		
		ctx.unused = 0;
		len = recv(new_sock, buf, BUF_LEN, 0);
		if(len > 0)
		{
			printf("srv(%d) recv %d\n", ctx.flag, len);
			if (ctx.flag == 0)
			{
				ret = cc_server_work((cc_proto_t *)buf, &ctx, len);
			}
			else
			{
				ret = cc_ctl_work((cc_proto_t *)buf, len, &ctx);
			}

			if (ctx.flag == 0)
			{
				ctx.unused = 1;
			}
		}
		else
		{
			if (len != 0)
			{
#ifdef WIN32
				printf("recv return %d error %d\n", len, GetLastError());
#else
				printf("recv return %d error %d\n", len, errno);
#endif
			}
		}

		delay(2000);
	}

	closesocket(new_sock);

	if (ctx.flag == 0)
	{
		ret = cc_del_tgt(ctx.ipv4, ctx.conn_port);
	}
	printf("thread_cc_work(%0x) mode(%d) exit.\n", ctx.tid, ctx.flag);
	return 0;
}

int fwd_select_wait_timeout(SOCKET sock, int sec)
{
	fd_set rfd;
	int nfds;
	struct timeval timeout;

	FD_ZERO(&rfd);
	FD_SET(sock, &rfd);
	timeout.tv_sec = sec;
	timeout.tv_usec = 0;
	nfds = select(sock + 1, &rfd, NULL, NULL, &timeout);
	if(nfds > 0)
	{
		FD_CLR(sock, &rfd);
	}

	return nfds;
}

THREAD_RETURN thread_cc_server(void *para)
{
	SOCKET listen_sock;
	SOCKET new_sock = INVALID_SOCKET;
	socklen_t sz;
	unsigned char *ip;
	struct sockaddr_in sa;
	thrd_cc_ctx_t ctx;
	int opt = 1;

	memcpy(&ctx, para, sizeof(thrd_cc_ctx_t));
	listen_sock = ctx.sock;

	fprintf(stdout,"[+]  thread_cc_server %d %d\n", ctx.flag, listen_sock);
	fprintf(stdout,"[+]  Waiting Connect On Port %u\n", ctx.port);
	fflush(stdout);

	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	sz = sizeof(sa);
	while(g_cc_cfg.b_exit == 0)
	{
#ifdef INVALID_SOCKET
		int nfds = fwd_select_wait_timeout(listen_sock, 3);
#else
 		int nfds = 1;
		set_recv_timeout(listen_sock, 3);
#endif
		if(nfds > 0)
		{
			lock_mutex();
			new_sock = accept(listen_sock, (struct sockaddr*)&sa, &sz);
			unlock_mutex();
		}
		else
		{
			if(nfds != 0)
			{
				printf("accept err = %d\n", errno); 
			}
			//printf("[+]  thread_cc_server %d timeout\n", ctx.flag);
			continue;
		}

		if(new_sock != INVALID_SOCKET)
		{
			ip = (unsigned char*)&sa.sin_addr.s_addr;
			fprintf(stdout,"[+]  Connect From %d.%d.%d.%d:%d On Port %d\n",
				ip[0],ip[1],ip[2],ip[3], htons(sa.sin_port), ctx.port);
			fflush(stdout);

			ctx.sock = new_sock;
			ctx.conn_port = htons(sa.sin_port);
			ctx.ipv4 = sa.sin_addr.s_addr;
			in_create_thread(thread_cc_work, &ctx, 0);
		}
		else
		{
#if WIN32
			fprintf(stdout,"[-]  Accept Failed On Port %d err=%d\n",
				ctx.port, GetLastError());
#else
			if (errno != EAGAIN)
			{
				fprintf(stdout,"[-]  Accept Failed On Port %d err=%d\n",
					ctx.port, errno);
			}
#endif
		}
	}// End while

	return 0;
}

int fwd_cc(uint16_t port1, uint16_t port2)
{
	SOCKET s[2];
	struct sockaddr_in sa;
	int i;
	int ret = 0;
	thrd_cc_ctx_t ctx[2] = {0};
	uint16_t p[2];

	p[0] = port1;
	p[1] = port2;

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;

	for(i = 0; i < 2; i++)
	{
		s[i] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if(s[i] == -1)
		{
			fprintf(stdout,"[-]  Create Socket %d Failed\n",i+1);
			ret = -1;
			break;
		}
		fprintf(stdout,"[+]  Create Socket %d Successed\n",i+1);
		fflush(stdout);

		sa.sin_port = htons(p[i]);
		if(bind(s[i], (struct sockaddr*)&sa, sizeof(sa)) != 0)
		{
			fprintf(stdout,"[-]  Bind On Port %u Failed\n",p[i]);
			ret = -1;
			break;
		}
		fprintf(stdout,"[+]  Bind On Port %u Success\n",p[i]);
		fflush(stdout);

		if(listen(s[i], 128) != 0)
		{
			fprintf(stdout,"[-]  Listen On Port %u Failed\n",p[i]);
			ret = -1;
			break;
		}
		fprintf(stdout,"[+]  Listen On Port %u Successed\n",p[i]);
		fflush(stdout);
	}
	
	if(ret < 0)
	{
		closesocket(s[0]);
		closesocket(s[1]);
		return -1;
	}

	g_server_port = port1;
	fprintf(stdout,"[+]  sock %d %d\n", s[0], s[1]);
	fflush(stdout);

	ctx[0].sock = s[0];
	ctx[0].flag = 0;
	ctx[0].port = port1;
	in_create_thread(thread_cc_server, &ctx[0], 0);
	//ctx[0].sock = accept(s[0], (struct sockaddr*)&sa, &sz);
	//printf("accept err = %d\n", errno); 
	//delay(100000);

	ctx[1].sock = s[1];
	ctx[1].flag = 1;
	ctx[1].port = port2;
	in_create_thread(thread_cc_server, &ctx[1], 0);

	return 0;
}


int fwd_tran(uint16_t port1, const char* ip2_str, uint16_t port2)
{
    int ret =0;
    char out[100];
    char out1[100],out2[100];
    unsigned long ip2;

    SOCKET ac;
    struct sockaddr_in sa;
    SOCKET s;

	s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

    if(s != -1)
    {
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port1);
        sa.sin_addr.s_addr = INADDR_ANY;

        if(bind(s, (struct sockaddr*)&sa, sizeof(sa)) == 0)
        {
            if(listen(s, SOMAXCONN) == 0)
            {
                xspf(out, sizeof(out),
                         "[+]  Listening On Port %d...\n", port1);
                log_file(out, D_INFO, 0xff);
            }
            else
            {
                log_file("[-]  Listen Failed\n", D_INFO, 0xff);
                ret = -1;
                closesocket(s);
                return ret;
            }
        }
        else
        {
            xspf(out, sizeof(out),
                     "[-]  Bind On Port %d Failed\n", port1);
            log_file(out, D_ERR, 0xff);
            ret = -1;
            closesocket(s);
            return ret;
        }
    }
    else
    {
        log_file("[-]  Create Socket Failed\n", D_ERR, 0xff);
        ret = -1;
        return ret;
    }

    ip2 = fwd_get_host(ip2_str);
    if(-1 == ip2)
    {
        xspf(out, sizeof(out),
                 "[-]  Reslove Host %s Failed...\n", ip2_str);
        log_file(out, D_ERR, 0xff);
        ret = -1;
        return ret;
    }

    while(1)
    {
        SOCKET tt[2];
        SOCKET s2;
        unsigned char* ip;
        socklen_t len = sizeof(sa);

        xspf(out, sizeof(out),
                 "[+]  Waiting Connect On Port %d...\n", port1);
        log_file(out, D_INFO, 0xff);

        ac = accept(s, (struct sockaddr*)&sa, &len);
        if(ac == -1)
        {
            log_file("[-]  Accept Failed...\n", D_ERR, 0xff);
            break;
        }

        ip =(unsigned char*)&sa.sin_addr.s_addr;
        xspf(out1, sizeof(out1), "%d.%d.%d.%d:%d",
                 ip[0], ip[1], ip[2], ip[3], htons(sa.sin_port));
        ip = (unsigned char*)&ip2;
        xspf(out2, sizeof(out1), "%d.%d.%d.%d:%d",
                 ip[0], ip[1], ip[2], ip[3], port2);
        xspf(out, sizeof(out),
                 "[+]  Connect From %s, Now Connect to %s\n", out1, out2);
        log_file(out, D_INFO, 0xff);

        sa.sin_port = htons(port2);
        sa.sin_addr.s_addr = ip2;
        s2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(connect(s2, (struct sockaddr*)&sa, sizeof(sa)) == 0)
        {
            tt[0]=ac;
            tt[1]=s2;
            xspf(out, sizeof(out),
                     "[+]  Connect %s Successed,Start Transfer...\n", out2);
            log_file(out, D_INFO, 0xff);

            in_create_thread(data_tran_thread, tt, 0);
        }
        else
        {
            xspf(out, sizeof(out),
                     "[-]  Connect %s Failed...\n", out2);
            log_file(out, D_ERR, 0xff);
            closesocket(s2);
            closesocket(ac);
        }
    }

    log_file("[+]  Tran end...\n", D_INFO, 0xff);

    closesocket(s);
    closesocket(ac);

    return ret;
}

int fwd_ctl(char* srv_ip, uint16_t port1, char* tgt_ip, uint16_t port2)
{
	cc_proto_t pkt = {0};
	cc_proto_t *q;

	int ret = -1;
	char out[100];
	char addr_info[100];
	SOCKET sock;
	unsigned char *ip[2];
	unsigned long ip1;
	struct sockaddr_in sa;
	int sa_len = sizeof(struct sockaddr);
	char buf[1024];

	pkt.ver = 0x01;
	pkt.flag = 0x55aa;
	pkt.b_new = 1;
	pkt.cmd = START_SLAVE;
	pkt.ctx.srv_port = port1;
	pkt.ctx.tgt_port = port2;
	xspf(pkt.ctx.srv_ip, sizeof(pkt.ctx.srv_ip), "%s", srv_ip);
	xspf(pkt.ctx.tgt_ip, sizeof(pkt.ctx.tgt_ip), "%s", tgt_ip);
	pkt.ctx.index = 0;

	// to do
	ip1 = fwd_get_host(srv_ip);
	if(ip1 == -1)
	{
		xspf(out, sizeof(out),
			"[-]  Reslove Host %s Failed...\n", srv_ip);
		log_file(out, D_ERR, 0xff);
		return -1;
	}

	ip[0] = (unsigned char*)&ip1;
	xspf(addr_info, sizeof(addr_info), "%d.%d.%d.%d:%d",
		ip[0][0],ip[0][1],ip[0][2],ip[0][3], port1);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock == -1)
	{
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(CC_CTL_PORT);
	sa.sin_addr.s_addr = (ip1);

	if (g_log_level)
	{
		xspf(out, sizeof(out), "[+]  Connect %s, Please Wait\n", addr_info);
		log_file(out, D_INFO, 0xff);
	}

	// reconnect 3 times
	if (connect(sock, (struct sockaddr*)&sa, sa_len) != 0)
	{
		if (g_log_level)
		{
			xspf(out, sizeof(out),
				"[-]  Connect %s Failed,Try Again..\n", addr_info);
			log_file(out, D_INFO, 0xff);
		}

		closesocket(sock);
		return -1;
	}

	if(send(sock, (char *)&pkt, sizeof(cc_proto_t), 0) <= 0)
	{
		if (g_log_level)
		{
			xspf(out, sizeof(out), "[-]  send %s Failed\n", addr_info);
			log_file(out, D_INFO, 0xff);
		}

		closesocket(sock);
		return -1;
	}

	ret = recv(sock, buf, 1024, 0);
	if(ret <= 0)
	{
		if (g_log_level)
		{
			xspf(out, sizeof(out), "[-]  recv %s Failed\n", addr_info);
			log_file(out, D_INFO, 0xff);
		}
		closesocket(sock);
		return -1;
	}

	q = (cc_proto_t *)buf;
	if (q->flag == 0x55aa && ret >= sizeof(cc_proto_t))
	{
		printf("send back %d ok=%d\n", q->cmd, q->b_ret);
	}

	closesocket(sock);

	return 0;
}

//-l 12341 12342
//-s relay host 12342 target host 3389
//12341->12342->
void help(const char* name)
{
	fprintf(stdout, "xsock %s (%s %s)\n", XSOCK_VERSION, __DATE__, __TIME__);
	fprintf(stdout, "\nUsage of Packet Transmit:\n");
	fprintf(stdout, "  %s -< v | l | t | s | p> <options> \n", name);
	fprintf(stdout, "[options:]\n");
	fprintf(stdout, "  -l <mapped port> <relay port>\n");
	fprintf(stdout, "  -t <local port> <target host> <target port>\n");
	fprintf(stdout, "  -s <relay host> <relay port> <target host> <target port>\n\n");
}

long cfg_get_port(const char *str)
{
    long port = EOF;
    port = atoi(str);
    if (port <= 0 || port > 65535)
    {
        fprintf(stdout,"\nERROR: %s: Wrong port number\n\n",str);
    }

    return port;
}

void cfg_set_file(FILE** fp,const char*file)
{
    *fp = fopen(file,"w");
    if (*fp == NULL)
    {
        fprintf(stdout,"\nERROR: Can not Write to File: %s\n\n",file);
    }
}

#define MAX_HOSTNAME 256
#define DEFAULT_PORT   80
#define DEFLISNUM   50
#define MAX_BUF_SIZE   10240
#define TIMEOUT    10000
#define HEADLEN    7

char str_err_msg[] = "Http/1.1 403 Forbidden\r\n\r\n<body><h1>403 Forbidden</h1></body>";
char str_conn_ok[] = "HTTP/1.0 200 OK\r\n\r\n";

char g_username[256];
char g_password[256];

typedef struct _socks4_req
{
    uint8_t Ver;
    uint8_t REP;
    uint16_t port;
    uint32_t ipv4;
    uint8_t other[1];
} Socks4Req;

typedef struct _socks5_req
{
    uint8_t Ver;
    uint8_t nMethods;
    uint8_t Methods[255];
} Socks5Req;

typedef struct _auth_req
{
    uint8_t Ver;
    uint8_t Ulen;
    uint8_t UserPass[1024];
} AuthReq;

typedef struct  _socks5_info
{
    uint8_t Ver;      // Version Number
    uint8_t CMD;      // 0x01==TCP CONNECT,0x02==TCP BIND,0x03==UDP ASSOCIATE
    uint8_t RSV;
    uint8_t ATYP;
    uint8_t IP_LEN;
    uint8_t szIP;
} Socks5Info;

typedef struct _ip_and_port
{
    uint32_t ipv4;
    uint16_t port;
} IPandPort;

typedef struct _socks5_conn
{
    uint8_t Ver;
    uint8_t REP;
    uint8_t RSV;
    uint8_t ATYP;
    IPandPort IPandPort;
} Socks5AnsConn;

typedef struct _socks5_udp_hdr
{
    uint8_t RSV[2];
    uint8_t FRAG;
    uint8_t ATYP;
    IPandPort IPandPort;
// BYTE DATA;
} Socks5UDPHead;

typedef struct _socket_info
{
    SOCKET socks;
    IPandPort IPandPort;
} SocketInfo;

typedef struct _socks5_para
{
    SocketInfo Local;
    SocketInfo Client;
    SocketInfo Server;
} Socks5Para;

// End Of Structure


THREAD_RETURN ss5_tcp_trans(void *ctx);
THREAD_RETURN ss5_udp_trans(void *ctx);
int in_connect_remote(SOCKET *ServerSocket,char *host_name, const uint16_t remote_port);

int ss5_get_host_port(char *recv_buf, int data_len, char *host_name, uint16_t *remote_port)
{
	int i;
    char *fp = recv_buf;

    for(i = 0; i < data_len && *fp != ':' && *fp != '\0' && *fp != '\r' && *fp != '/'; i++)
    {
        host_name[i] = *fp++;
        if(*fp == ':')
		{
            *remote_port = (uint16_t)atoi(fp + 1);
		}
        else
		{
			*remote_port = DEFAULT_PORT;
		}
    }

	return 0;
}

char * ss5_get_url_root(char * recv_buf,int data_len,int *HostNaneLen)
{
	int i;

    for(i = 0; i < data_len; i++)
    {
        if(recv_buf[i] == '/')
        {
            *HostNaneLen = i;
            return &recv_buf[i];
        }
    }

    return NULL;
}

int ss5_chk_req(char *recv_buf, int *MethodLength)
{
    if(!xstrnicmp(recv_buf, "GET ", 4))
    {
        *MethodLength = 4;
        return 1;
    }

    if(!xstrnicmp(recv_buf,"POST ",5))
    {
        *MethodLength = 5;
        return 1;
    }

    if(!xstrnicmp(recv_buf,"CONNECT ",8))
    {
        *MethodLength = 8;
        return 2;
    }

	if(!xstrnicmp(recv_buf,"HEAD ",5))
	{
		*MethodLength = 5;
		return 1;
	}

    return 0;
}

int ss5_mod_req(char *send_buf,char *recv_buf,int data_len,int MethodLength)
{
	int len;
	int HedLen = 0;
	char * p;
	
    strncpy(send_buf, recv_buf, MethodLength);

	if(strncmp(recv_buf + MethodLength, "https://", HEADLEN + 1) == 0)
	{
		log_file("get https", D_WARN, 0xff);
	}

    if(strncmp(recv_buf + MethodLength, "http://", HEADLEN))
	{
        return 0;
	}

	len = data_len - MethodLength - HEADLEN;
    p = ss5_get_url_root(recv_buf+MethodLength+HEADLEN, len, &HedLen);
    if(p == NULL)
	{
        return 0;
	}

    memcpy(send_buf + MethodLength, p, len - HedLen);

    return data_len-HEADLEN-HedLen;
}

int ss5_send_req(SOCKET* pair_socks, char *send_buf, char *recv_buf, int data_len)
{
    char host_name[MAX_HOSTNAME] = {0};
    uint16_t remote_port = 0;
    int ret = 0, MethodLength = 0, SendLength = 0;

    ret = ss5_chk_req(recv_buf, &MethodLength);
	if (ret == 0)
	{
		return 0;
	}
	else if (ret == 1)
	{
		SendLength = ss5_mod_req(send_buf, recv_buf, data_len, MethodLength);
		if(!SendLength)
		{
			return 0;
		}

		ss5_get_host_port(recv_buf + MethodLength + HEADLEN,
			data_len - MethodLength - HEADLEN, host_name, &remote_port);

		if(!in_connect_remote(&pair_socks[1], host_name, remote_port))
		{
			return 0;
		}

		if(send(pair_socks[1], send_buf, SendLength,0) == -1)
		{
			return 0;
		}
	}
	else if (ret == 2)
	{
		ss5_get_host_port(recv_buf + MethodLength, data_len-MethodLength,
			host_name, &remote_port);
		if(!in_connect_remote(&pair_socks[1],host_name,remote_port))
		{
			return 0;
		}
		send(pair_socks[0], str_conn_ok, strlen(str_conn_ok)+1,0);
	}

    if(pair_socks[0] && pair_socks[1])
    {
        in_create_thread(ss5_tcp_trans, pair_socks, 1);
    }
	else
	{
        return 0;
	}

    return 1;
}

/////////////////////////////////////////////////////
int ss5_auth(SOCKET* pair_socks, char *recv_buf, int data_len)
{
	int ret = 0;
    Socks5Req *sq;
    char Method[2]= {0x05,0};

	if (data_len < 2)
	{
		return 0;
	}

    sq=(Socks5Req *)recv_buf;
	////xspf("%d,%d,%d,%d,%d\n",sq->Ver,sq->nMethods,sq->Methods[0],sq->Methods[1],sq->Methods[2]);
    if(sq->Ver != 5)
	{
        return sq->Ver;
	}

	//00，无需认证；01，GSSAPI；02，需要用户名和PASSWORD
    if(sq->Methods[0] == 0 || sq->Methods[0] == 2)
    {
        if(strlen(g_username)==0)
            Method[1]=0x00;
        else
            Method[1]=0x02;
        if(send(pair_socks[0],Method,2,0) == -1)
		{
            return 0;
		}
    }
	else
	{
        return 0;
	}

    if(Method[1] == 0x02)//00，无需认证；01，GSSAPI；02，需要用户名和PASSWORD
    {
		AuthReq *aq;
		int PLen;
        char USER[256];
        char PASS[256];
        memset(USER,0,sizeof(USER));
        memset(PASS,0,sizeof(PASS));
        ret = recv(pair_socks[0],recv_buf,MAX_BUF_SIZE,0);
        if(ret == -1 || ret == 0)
		{
            return 0;
		}

		aq=(AuthReq *)recv_buf;
        if(aq->Ver != 1)
		{
            return 0;
		}

        if((aq->Ulen!=0)&&(aq->Ulen<=256))
        {
        	memcpy(USER,recv_buf+2,aq->Ulen);
        }

        PLen = recv_buf[2+aq->Ulen];
        if(PLen != 0 && PLen <= 256)
		{
            memcpy(PASS,recv_buf+3+aq->Ulen,PLen);
		}
        //printf("USER %s\nPASS %s\n",USER,PASS);
        //0=login successfully,0xFF=failure;
        if(!strcmp(g_username,USER) && !strcmp(g_password,PASS))
        {
            recv_buf[1] = 0x00;
            //printf("Socks5 ss5_auth Passed\n");
        }
        else
        {
            recv_buf[1] = 0xFF;
            //printf("Invalid g_password\n");
        }

        if(send(pair_socks[0],recv_buf,2,0) == -1)
		{
            return 0;
		}
    }

    return 1;
}

char *ss5_get_out_ip(char *OutIP)
{
	int i,j;
    char addr[16];
    struct hostent * pHost;

    pHost = gethostbyname("");

    for(i = 0; pHost!= NULL && pHost->h_addr_list[i]!= NULL; i++)
    {

        OutIP[0]=0;
        for(j = 0; j < pHost->h_length; j++)
        {
            if(j > 0)
			{
				xspf(OutIP, 256, "%s.", OutIP);
			}
            xspf(addr, sizeof(addr),
				"%u", (uint32_t)((unsigned char*)pHost->h_addr_list[i])[j]);
            xspf(OutIP, 256, "%s%s", OutIP, addr);
        }
    }

    return OutIP;
}

unsigned long ss5_get_host_ip(char *host_name)
{
	//char *p;
	struct hostent *hostent = NULL;
	struct in_addr iaddr;

	hostent = gethostbyname(host_name);
	if (hostent == NULL || hostent->h_addr == NULL)
	{
		return 0;
	}

	iaddr.s_addr = *(uint32_t *)(hostent->h_addr);
	//p = inet_ntoa(iaddr);

	return iaddr.s_addr;
}

int ss5_get_addr_port(char *recv_buf, int data_len, int ATYP, char *host_name, uint16_t *remote_port)
{
    char *str_ip;
    struct sockaddr_in in;
    Socks5Info *Socks5Request = (Socks5Info *)recv_buf;

	if (data_len < 4)
	{
		return 0;
	}

    if(ATYP==2) //Socks v4 !!!
    {
		Socks4Req *s4_req = (Socks4Req *)recv_buf;

        *remote_port=ntohs(s4_req->port);
        if(recv_buf[4]!=0x00) //USERID !!
		{
            in.sin_addr.s_addr = s4_req->ipv4;
		}
        else
		{
			in.sin_addr.s_addr = fwd_get_host((char*)&s4_req->other+1);
		}

		str_ip = inet_ntoa(in.sin_addr);
		log_file(str_ip, D_DBG, 0xff);
        memcpy(host_name, str_ip, strlen(str_ip));
        return 1;
    }

	//ATYP=0x01代表IP V4地址 0x03代表域名;
    if((Socks5Request->Ver==5)&&(ATYP==1))
    {
		char *p;
        IPandPort *IPP=(IPandPort *)&Socks5Request->IP_LEN;
        in.sin_addr.s_addr = IPP->ipv4;
		p = inet_ntoa(in.sin_addr);
        memcpy(host_name, p, strlen(p));
        *remote_port = ntohs(IPP->port);
    }
    else if((Socks5Request->Ver==5)&&(ATYP==3))
    {
        memcpy(host_name, &Socks5Request->szIP, Socks5Request->IP_LEN);
        memcpy(remote_port, &Socks5Request->szIP+Socks5Request->IP_LEN, 2);
        *remote_port=ntohs(*remote_port);
    }
	else if((Socks5Request->Ver==0)&&(Socks5Request->CMD==0)&&(ATYP==1))
    {
		char *p;
        IPandPort *IPP=(IPandPort *)&Socks5Request->IP_LEN;
        in.sin_addr.s_addr = IPP->ipv4;
		p = inet_ntoa(in.sin_addr);
		memcpy(host_name, p, strlen(p));
        *remote_port = ntohs(IPP->port);
        return 10; //return Data Enter point
    }
	else if((Socks5Request->Ver==0)&&(Socks5Request->CMD==0)&&(ATYP==3))
    {
        memcpy(host_name, &Socks5Request->szIP, Socks5Request->IP_LEN);
        memcpy(remote_port, &Socks5Request->szIP+Socks5Request->IP_LEN, 2);
        *remote_port=ntohs(*remote_port);
        return 7+Socks5Request->IP_LEN; //return Data Enter point
    }
	else
	{
        return 0;
	}

    return 1;
}

int in_connect_remote(SOCKET *ServerSocket,char *host_name,const uint16_t remote_port)
{
	//char host[256] = {0};
	uint32_t TimeOut = TIMEOUT;
    struct sockaddr_in Server;
    memset(&Server, 0, sizeof(Server));
    Server.sin_family = AF_INET;
    Server.sin_port = htons(remote_port);
	Server.sin_addr.s_addr = inet_addr(host_name);

    if (Server.sin_addr.s_addr == INADDR_NONE)
    {
		Server.sin_addr.s_addr = fwd_get_host(host_name); 
		if (Server.sin_addr.s_addr == 0)
		{
			log_file("s_addr 0\n", D_INFO, 0xff);
            return 0;
		}
    }

	// Create Socket
    *ServerSocket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (*ServerSocket == -1)
	{
		log_file("socket error\n", D_INFO, 0xff);
        return 0;
	}

    setsockopt(*ServerSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut,sizeof(TimeOut));
    if (connect(*ServerSocket, (const struct sockaddr *)&Server,sizeof(Server)) != 0)
    {
        printf("Fail To Connect To Remote Host\n");
        closesocket(*ServerSocket);
        return 0;
    }

	log_file("connect ok\n", D_INFO, 0xff);
    return 1;
}

int TalkWithClient(SOCKET *pair_socks, char *recv_buf, int data_len, char *host_name, uint16_t *remote_port)
{
    int ret = 0;
	Socks5Info *Socks5Request;

	//g_username g_password ss5_auth
    ret = ss5_auth(pair_socks, recv_buf, data_len);
    if(ret == 0)
	{
		log_file("ss5_auth failed", D_INFO, 0xff);
		return 0;
	}

	//Processing Socks v4 requests......
    if(ret == 4) 
    {   //The third parameter ATYP==2 is not used for Socks5 protocol,I use it to flag the socks4 request.
        if(!ss5_get_addr_port(recv_buf, data_len, 2, host_name, remote_port))
		{
			log_file("protocol v4", D_INFO, 0xff);
            return 0;
		}
		return 4;
    }

	//Processing Socks v5 requests......
    data_len = recv(pair_socks[0], recv_buf, MAX_BUF_SIZE, 0);
    if(data_len == -1 || data_len == 0)
	{
		char out[256];
		xspf(out, sizeof(out), "Processing Socks v5 requests error=%d", data_len);
		log_file(out, D_INFO, 0xff);
        return 0;
	}

	Socks5Request = (Socks5Info *)recv_buf;
    if (Socks5Request->Ver != 5)
    {
        log_file("Invalid Socks 5 Request\n", D_ERR, 0xff);
        return 0;
    }

	//Get IP Type //0x01==IP V4地址 0x03代表域名;0x04代表IP V6地址;not Support
    if((Socks5Request->ATYP==1)||(Socks5Request->ATYP==3))
    {
        if(!ss5_get_addr_port(recv_buf, data_len, Socks5Request->ATYP, host_name, remote_port))
		{
			char out[256];
			xspf(out, sizeof(out), "ss5_get_addr_port error=%d", errno);
			log_file(out, D_INFO, 0xff);
            return 0;
		}
    }
	else
	{
		char out[256];
		xspf(out, sizeof(out), "Get IP Type error=%d", errno);
		log_file(out, D_INFO, 0xff);
		return 0;
	}

	//Get and return the work mode. 1:TCP CONNECT   3:UDP ASSOCIATE
    if((Socks5Request->CMD == 1)||(Socks5Request->CMD == 3))
	{
        return Socks5Request->CMD;
	}

    return 0;
}

int ss5_create_udp_sock(Socks5AnsConn *SAC, SOCKET *socks)
{
	SOCKET Locals;
	int structsize;
    char szIP[256];
    struct sockaddr_in UDPServer;
    struct sockaddr_in in;

    memset(&in, 0, sizeof(struct sockaddr_in));
    structsize = sizeof(struct sockaddr_in);
    UDPServer.sin_family=AF_INET;
    UDPServer.sin_addr.s_addr= INADDR_ANY;
    UDPServer.sin_port=INADDR_ANY;
    Locals = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(Locals == -1)
    {
        //printf("UDP socket create failed.\n");
        return 0;
    }
    if(bind(Locals,(struct sockaddr *)&UDPServer, sizeof(UDPServer)) == -1)
    {
        //printf("UDP socket bind failed.\n");
        return 0;
    }

    //UINT TimeOut = TIMEOUT;
	//setsockopt(Locals,SOL_SOCKET,SO_RCVTIMEO,(char *)&TimeOut,sizeof(TimeOut));

    *socks = Locals;
    getsockname(Locals,(struct sockaddr *)&in,&structsize);
    SAC->IPandPort.ipv4 = inet_addr(ss5_get_out_ip(szIP));
    SAC->IPandPort.port = in.sin_port;
	//printf("UDP Bound to %s:%d\r\n", szIP, ntohs(in.sin_port));
    return 1;
}

static int thread_count = 0;

THREAD_RETURN proxy_thread(void* ctx)
{
	int ret = 0;
	char *recv_buf;
	char *send_buf;
	int data_len = 0, Flag = 0, ProtocolVer = 0;
	uint16_t remote_port = 0;
	char host_name[MAX_HOSTNAME] = {0};
	Socks5AnsConn SAC = {0};

	SOCKET* pair_socks = (SOCKET*)ctx;

	//log_file("Enter proxy thread.\n", D_DBG, 0xff);

	recv_buf = (char*)malloc(MAX_BUF_SIZE);
	if (recv_buf == NULL)
	{
		log_file("Fail To Allocate memory\n", D_ERR, 0xff);
		return 0;
	}

	send_buf = (char*)malloc(MAX_BUF_SIZE);
	if (send_buf == NULL)
	{
		free(recv_buf);
		log_file("Fail To Allocate memory\n", D_ERR, 0xff);
		return 0;
	}
    memset(recv_buf, 0, MAX_BUF_SIZE);
    memset(send_buf, 0, MAX_BUF_SIZE);

	lock_mutex();
	thread_count++;
	unlock_mutex();

    data_len = recv(pair_socks[0], recv_buf, MAX_BUF_SIZE, 0);
    if(data_len < 1)
	{
        goto exit;
	}

    if(ss5_send_req(pair_socks, send_buf, recv_buf, data_len))
	{
		goto exit;
	}

    Flag = TalkWithClient(pair_socks, recv_buf, data_len, host_name, &remote_port);
	printf("TalkWithClient return Flag %d.\n", Flag);
	switch(Flag)
	{
		case 0:
			/*SAC.Ver=0x05;
			SAC.REP=0x01;
			SAC.ATYP=0x01;
			send(pair_socks[0], (char *)&SAC, 10, 0);*/
			goto exit;
			break;
		case 1: //TCP CONNECT
			{
				ProtocolVer=5;
				if(!in_connect_remote(&pair_socks[1], host_name, remote_port))
				{
					SAC.REP = 0x01;
				}
				SAC.Ver=0x05;
				SAC.ATYP=0x01;
				if(send(pair_socks[0], (char *)&SAC, 10, 0) == -1)
				{
					printf("send failure %d.\n", errno);
					goto exit;
				}

				if(SAC.REP == 0x01) // general SOCKS server failure
				{
					printf("general SOCKS server failure SAC.REP %d.\n", SAC.REP);
					goto exit;
				}
			}
			break;
		case 3: //UDP ASSOCIATE
			{   
				Socks5Para sPara;
				struct sockaddr_in in;
				socklen_t len = sizeof(struct sockaddr_in);

				log_file("Enter UDP ASSOCIATE.\n", D_INFO, 0xff);

				ProtocolVer = 5;
				memset(&in, 0, sizeof(struct sockaddr_in));
				memset(&sPara,0,sizeof(Socks5Para));
				
				//Save the client connection information(client IP and source port)
				getpeername(pair_socks[0], (struct sockaddr *)&in, &len);

				if(inet_addr(host_name)==0)
				{
					sPara.Client.IPandPort.ipv4 = in.sin_addr.s_addr;
				}
				else
				{
					sPara.Client.IPandPort.ipv4 = fwd_get_host(host_name);
				}

				////printf("Accept ip:%s\n",inet_ntoa(in.sin_addr));
				sPara.Client.IPandPort.port= htons(remote_port);/////////////////
				sPara.Client.socks=pair_socks[0];
				if(!ss5_create_udp_sock(&SAC,&sPara.Local.socks)) //Create a local UDP socket
				{
					SAC.REP=0x01;
				}

				SAC.Ver=5;
				SAC.ATYP=1;

				if(send(pair_socks[0], (char *)&SAC, 10, 0) == -1)
					goto exit;

				if(SAC.REP==0x01) // general SOCKS server failure
					goto exit;

				sPara.Local.IPandPort=SAC.IPandPort; //Copy local UDPsocket data structure to sPara.Local
				////// Create UDP Transfer thread
				ret = in_create_thread(ss5_udp_trans, &sPara, 1);
				if (ret != 0)
				{
					//printf("ss5_udp_trans Thread %d Exit.\n",n);
					goto exit;
				}

				goto exit;
				////////////////////
			}
			break;
		case 4: // Socks v4! I use the return value==4 to flag the Socks v4 request.
			{
				Socks4Req s4_req;

				ProtocolVer=4;
				memset(&s4_req, 0, 9);
				if(!in_connect_remote(&pair_socks[1],host_name,remote_port))
				{
					s4_req.REP = 0x5B; //REJECT
				}
				else
				{
					s4_req.REP = 0x5A; //GRANT
				}
				if(send(pair_socks[0], (char *)&s4_req, 8, 0) == -1)
				{
					goto exit;
				}

				if(s4_req.REP==0x5B)   //in_connect_remote failed,closesocket and free some point.
					goto exit;
			}
			break;
		default:
			goto exit;
			break;
	}

    if(pair_socks[0] && pair_socks[1])
    {
        //printf("Socks%d TCP Session-> %s:%d\n",ProtocolVer,host_name,remote_port);
        in_create_thread(ss5_tcp_trans, pair_socks, 1);
    }

exit:
	//log_file("Exit proxy thread.\n", D_DBG, 0xff);
	lock_mutex();
	thread_count--;
	unlock_mutex();

    closesocket(pair_socks[0]);
    closesocket(pair_socks[1]);
    free(pair_socks);
    free(send_buf);
    free(recv_buf);
    return 0;
}

int fwd_proxy(uint16_t port)
{
	int ret = 0;
	char out[100];
	struct sockaddr_in sa = {0};
	SOCKET server_sock;

    server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server_sock == -1)
	{
		log_file("[-]  Create Socket Failed\n", D_ERR, 0xff);
        return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1)
	{
		xspf(out, sizeof(out), "[-]  Bind On Port %d Failed\n", port);
		log_file(out, D_ERR, 0xff);
        return -1;
	}

    if(listen(server_sock, 32) == -1)//SOMAXCONN
	{
		xspf(out, sizeof(out), "[-]  Listen On Port %d Failed\n", port);
		log_file(out, D_ERR, 0xff);
        return -1;
	}

	xspf(out, sizeof(out), "[+]  Listen On Port %d Success\n", port);
	log_file(out, D_INFO, 0xff);

    while(g_cc_cfg.b_exit == 0)
    {
		SOCKET s;
		SOCKET *pair_socks;
        s = accept(server_sock, NULL, NULL);
		if(s == -1)
		{
			log_file("[-]  Accept Failed...\n", D_ERR, 0xff);
			delay(500);
			continue;
		}

// 		xspf(out, sizeof(out), "[+]  accept %d Success\n", s);
// 		log_file(out, D_DBG, 0xff);

        pair_socks = (SOCKET*)malloc(sizeof(SOCKET) * 2);
        if (pair_socks == NULL)
        {
			log_file("Fail To Allocate memory\n", D_ERR, 0xff);
            continue;
        }
        pair_socks[0] = s;
		pair_socks[1] = 0;

		in_create_thread(proxy_thread, pair_socks, 0);
    }

	return ret;
}

////////////////////////////////
int ss5_udp_send(SOCKET s, char *buff, int nBufSize, struct sockaddr_in *to,int tolen)
{
    int nBytesLeft = nBufSize;
    int idx = 0, nBytes = 0;
    while(nBytesLeft > 0)
    {
        nBytes = sendto(s, &buff[idx], nBytesLeft, 0, (struct sockaddr *)to, tolen);
        if(nBytes == -1)
        {
            //printf("Failed to send buffer to socket %d.\r\n", WSAGetLastError());
            return -1;
        }
        nBytesLeft -= nBytes;
        idx += nBytes;
    }
    return idx;
}

THREAD_RETURN ss5_udp_trans(void *ctx)
{
	fd_set readfd;
	Socks5Para *sPara = (Socks5Para *)ctx;
    struct sockaddr_in SenderAddr;
    int   SenderAddrSize=sizeof(SenderAddr),data_length=0,result;
    char RecvBuf[MAX_BUF_SIZE];
    struct sockaddr_in UDPClient,UDPServer;
    memset(&UDPClient, 0, sizeof(struct sockaddr_in));
    memset(&UDPServer, 0, sizeof(struct sockaddr_in));
    UDPClient.sin_family = AF_INET;
    UDPClient.sin_addr.s_addr = sPara->Client.IPandPort.ipv4;
    UDPClient.sin_port = sPara->Client.IPandPort.port;
    /*/test
    Socks5UDPHead test;
    memset(&test,0,sizeof(Socks5UDPHead));
    test.RSV[0]=0x05;
    test.ATYP=0x01;
    test.IPandPort=sPara->Local.IPandPort;
    if(sendto(sPara->Local.socks,(char*)&test, 10,0,(struct sockaddr FAR *)&UDPClient,sizeof(UDPClient)) == -1)
    {
       //printf("test sendto server error.\n");
       return;
    }*/
//printf("ss5_udp_trans thread start......\n");

    while(g_cc_cfg.b_exit == 0)
    {
        FD_ZERO(&readfd);
        FD_SET(sPara->Local.socks, &readfd);
        FD_SET(sPara->Client.socks, &readfd);
        result = select(sPara->Local.socks+1,&readfd,NULL,NULL,NULL);
        if(result < 0 && errno != EINTR)
        {
#ifdef WIN32
			printf("Select error=%d.\r\n", GetLastError());
#else
            printf("Select error=%d.\r\n", errno);
#endif
            break;
        }
        if(FD_ISSET(sPara->Client.socks, &readfd))
            break;
        if(FD_ISSET(sPara->Local.socks, &readfd))
        {
            memset(RecvBuf,0,MAX_BUF_SIZE);
            data_length=recvfrom(sPara->Local.socks,
                                RecvBuf+10, MAX_BUF_SIZE-10, 0, (struct sockaddr *)&SenderAddr, &SenderAddrSize);
            if(data_length==-1)
            {
                //printf("ss5_udp_trans recvfrom error.\n");
                break;
            }//SenderAddr.sin_addr.s_addr==sPara->Client.IPandPort.ipv4&&
            if(SenderAddr.sin_port==sPara->Client.IPandPort.port)//Data come from client
            {
				int DataPoint;
                //////这里要先修改udp数据报头
                uint16_t remote_port = 0;
                char host_name[MAX_HOSTNAME];
                memset(host_name,0,MAX_HOSTNAME);
                DataPoint = ss5_get_addr_port(RecvBuf+10, data_length, RecvBuf[13], host_name, &remote_port);
                if(DataPoint)
                {
                    ////printf("Data come from client IP: %s:%d | %d Bytes.\n",
                    // inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),data_length);
                    //send data to server
                    ////printf("IP: %s:%d || DataPoint: %d\n",host_name,remote_port,DataPoint);
                    UDPServer.sin_family=AF_INET;
                    UDPServer.sin_addr.s_addr= fwd_get_host(host_name);
                    UDPServer.sin_port=htons(remote_port);
                    result=ss5_udp_send(sPara->Local.socks,RecvBuf+10+DataPoint, data_length-DataPoint,&UDPServer,sizeof(UDPServer));
                    if(result == -1)
                    {
                        //printf("sendto server error\n");
                        break;
                    }
                    printf("Data(%d) sent to server succeed.|| Bytes: %d\n",data_length-DataPoint,result);
                } else break;
            } else if(SenderAddr.sin_port==UDPServer.sin_port)//Data come from server
            {   //SenderAddr.sin_addr.s_addr==UDPServer.sin_addr.s_addr&&
                //send data to client
                ////printf("Data come from server IP: %s:%d | %d Bytes.\n",
                // inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),data_length);
                Socks5UDPHead *UDPHead = (Socks5UDPHead*)RecvBuf;
                memset(UDPHead,0,10);
                UDPHead->ATYP=0x01;
                UDPHead->IPandPort=sPara->Client.IPandPort;
                //UDPHead->IPandPort.ipv4 =SenderAddr.sin_addr.s_addr;
                //UDPHead->IPandPort.port=SenderAddr.sin_port;
                //memcpy(&UDPHead->DATA-2,RecvBuf,data_length);//UDPHead->DATA-2!!!!!!!!!!!!
                result=ss5_udp_send(sPara->Local.socks,RecvBuf,data_length+10,&UDPClient,sizeof(UDPClient));
                if(result == -1)
                {
                    ////printf("sendto client error\n");
                    break;
                }
                //printf("Data(%d) sent to client succeed.|| Bytes: %d\n",data_length+10,result);
            } else
            {
                //printf("!!!!!The data are not from client or server.drop it.%s\n",inet_ntoa(SenderAddr.sin_addr));
            }
        }
        delay(5);
    }
    closesocket(sPara->Local.socks);
    closesocket(sPara->Client.socks);

	return 0;
}

THREAD_RETURN ss5_tcp_trans(void *ctx)
{
	SOCKET* pair_socks = (SOCKET*)ctx;
    SOCKET ClientSocket = pair_socks[0];
    SOCKET ServerSocket = pair_socks[1];
    struct timeval timeset;
    fd_set readfd,writefd;
    int result;
    char read_in1[MAX_BUF_SIZE],send_out1[MAX_BUF_SIZE],send_buf[MAX_BUF_SIZE];
    char read_in2[MAX_BUF_SIZE],send_out2[MAX_BUF_SIZE];
    int read1=0,totalread1=0,send1=0;
    int read2=0,totalread2=0,send2=0;
    int sendcount1,sendcount2;
    int maxfd;
    maxfd = max(ClientSocket,ServerSocket) + 1;
    memset(read_in1,0,MAX_BUF_SIZE);
    memset(read_in2,0,MAX_BUF_SIZE);
    memset(send_out1,0,MAX_BUF_SIZE);
    memset(send_out2,0,MAX_BUF_SIZE);
    timeset.tv_sec=TIMEOUT;
    timeset.tv_usec=0;
    while(1)
    {
        FD_ZERO(&readfd);
        FD_ZERO(&writefd);
        FD_SET(ClientSocket, &readfd);
        FD_SET(ClientSocket, &writefd);
        FD_SET(ServerSocket, &writefd);
        FD_SET(ServerSocket, &readfd);
        result = select(maxfd, &readfd, &writefd, NULL, &timeset);
        if(result < 0 && errno != EINTR)
        {
#ifdef WIN32
			printf("Select error=%d.\r\n", GetLastError());
#else
            printf("Select error=%d.\r\n", errno);
#endif
            break;
        }
        else if(result == 0)
        {
            printf("Socket time out.\r\n");
            break;
        }

        if(FD_ISSET(ServerSocket, &readfd))
        {
            if(totalread2<MAX_BUF_SIZE)
            {
                read2=recv(ServerSocket,read_in2,MAX_BUF_SIZE-totalread2, 0);
                if(read2==0)break;
                if((read2<0) && (errno!=EINTR))
                {
                    printf("Read ServerSocket data error,maybe close?\r\n\r\n");
                    break;
                }
                memcpy(send_out2+totalread2,read_in2,read2);
                totalread2+=read2;
                memset(read_in2,0,MAX_BUF_SIZE);
            }
        }
        if(FD_ISSET(ClientSocket, &writefd))
        {
            int err2=0;
            sendcount2=0;
            while(totalread2>0)
            {
                send2=send(ClientSocket, send_out2+sendcount2, totalread2, 0);
                if(send2==0)break;
                if((send2<0) && (errno!=EINTR))
                {
                    printf("Send to ClientSocket unknow error.\r\n");
                    err2=1;
                    break;
                }
                if((send2<0) && (errno==ENOSPC)) break;
                sendcount2+=send2;
                totalread2-=send2;
            }
            if(err2==1) break;
            if((totalread2>0) && (sendcount2 > 0))
            {
                /* move not sended data to start addr */
                memcpy(send_out2, send_out2+sendcount2, totalread2);
                memset(send_out2+totalread2, 0, MAX_BUF_SIZE-totalread2);
            }
            else
                memset(send_out2,0,MAX_BUF_SIZE);
        }
        if(FD_ISSET(ClientSocket, &readfd))
        {
            if(totalread1<MAX_BUF_SIZE)
            {
                read1=recv(ClientSocket, read_in1, MAX_BUF_SIZE-totalread1, 0);
                if((read1==-1) || (read1==0))
                {
                    break;
                }
                memcpy(send_out1+totalread1,read_in1,read1);
                totalread1+=read1;
                memset(read_in1,0,MAX_BUF_SIZE);
            }
            if(ss5_send_req(pair_socks,send_buf,send_out1,totalread1))
                totalread1=0;
        }
        if(FD_ISSET(ServerSocket, &writefd))
        {
            int err=0;
            sendcount1=0;
            while(totalread1>0)
            {
                send1=send(ServerSocket, send_out1+sendcount1, totalread1, 0);
                if(send1==0)break;
                if((send1<0) && (errno!=EINTR))
                {
                    err=1;
                    break;
                }
                if((send1<0) && (errno==ENOSPC)) break;
                sendcount1+=send1;
                totalread1-=send1;
            }
            if(err==1) break;
            if((totalread1>0) && (sendcount1>0))
            {
                memcpy(send_out1,send_out1+sendcount1,totalread1);
                memset(send_out1+totalread1,0,MAX_BUF_SIZE-totalread1);
            }
            else
                memset(send_out1,0,MAX_BUF_SIZE);
        }
        delay(5);
    }
    closesocket(ClientSocket);
    closesocket(ServerSocket);

	return 0;
}


int set_recv_timeout(SOCKET sock, int sec)
{
	int ret = 0;
	struct timeval recv_tmo;
	recv_tmo.tv_sec = sec;
	recv_tmo.tv_usec = 0;

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
		(char *)&recv_tmo, sizeof(recv_tmo));
	if (ret != 0)
	{
		printf("set accept timeout failed");
	}

	return ret;
}

THREAD_RETURN thread_slave(void* para)
{
	thread_slave_ctx_t ctx = {0};
	memcpy(&ctx, para, sizeof(thread_slave_ctx_t));

	printf("thread_slave(%d) enter.\n", ctx.index);
	printf("new slave %s:%d->%s:%d\n", 
		ctx.srv_ip, ctx.srv_port, ctx.tgt_ip, ctx.tgt_port);

	while(g_cc_cfg.b_exit == 0 && g_cc_cfg.b_stop == 0)
	{
		fwd_slave(ctx.srv_ip, ctx.srv_port, ctx.tgt_ip, ctx.tgt_port);
		delay(300 * 1000);
	}

	printf("thread_slave(%d) exit.\n", ctx.index);

	return 0;
}

THREAD_RETURN thread_listen(void* para)
{
	thread_slave_ctx_t ctx = {0};
	memcpy(&ctx, para, sizeof(thread_slave_ctx_t));

	printf("thread_listen enter.\n");
	printf("listen %d->%d\n", ctx.srv_port, ctx.srv_port + 1);

	fwd_listen(ctx.srv_port, ctx.srv_port + 1, 1);

	printf("thread_listen exit.\n");
	return 0;
}

int fwd_cc_mode(void* para)
{
	int ret;
	uint16_t *ports = (uint16_t *)para;

	printf("fwd_cc_mode enter.\n");

	printf("port %d %d\n", ports[0], ports[1]);
	if (ports[0] > 0 && ports[1] > 0)
	{
		ret = fwd_cc(ports[0], ports[1]);
	}
	else
	{
		ret = fwd_cc(CC_PORT, CC_CTL_PORT);
	}

	while(g_cc_cfg.b_exit == 0 && ret == 0)
	{
		delay(30 * 1000);
	}

	printf("fwd_cc_mode exit.\n");

	return 0;
}

int cc_chk_pkt_hdr(cc_proto_t *p)
{
	if (p->flag != 0x55aa)
	{
		return -1;
	}

	return 0;
}

int cc_client_work(cc_proto_t *p, SOCKET sock)
{
	int ret = 0;

	if (cc_chk_pkt_hdr(p) < 0)
	{
		return -1;
	}

	printf("cmd %x\n", p->cmd);

	if (p->cmd == START_SLAVE)
	{
		printf("cc client %s:%d->%s:%d\n", 
			p->ctx.srv_ip, p->ctx.srv_port, p->ctx.tgt_ip, p->ctx.tgt_port);
		if (p->b_new)
		{
			in_create_thread(thread_slave, &p->ctx, 0);
			p->cmd = START_SLAVE_FIN;
		}
	}

	if (p->b_stop)
	{
		g_cc_cfg.b_stop = 1;
	}

	if (p->b_exit)
	{
		g_cc_cfg.b_exit = 1;
	}

	p->b_ret = 1;

	ret = send(sock, (char *)p, sizeof(cc_proto_t), 0);
	if(ret <= 0)
	{
		printf("[-]  send Failed\n");
	}
	else
	{
		printf("[+]  send %d\n", ret);
	}

	return 0;
}

int cc_server_work(cc_proto_t *p, thrd_cc_ctx_t *ctx, int len)
{
	int ret;
	SOCKET new_sock = ctx->sock;

	if (cc_chk_pkt_hdr(p) < 0)
	{
		return -1;
	}

	switch (p->cmd)
	{
	case HEART_BEAT:
		printf("host(%x) heart beat\n", ctx->ipv4);
		cc_add_tgt(ctx);
		break;
	case START_SLAVE_FIN:
		printf("cc server %s:%d->%s:%d\n", 
			p->ctx.srv_ip, p->ctx.srv_port, p->ctx.tgt_ip, p->ctx.tgt_port);

		if (p->b_new)
		{
			in_create_thread(thread_listen, &p->ctx, 0);
		}
		p->cmd = HEART_BEAT;
		ret = send(new_sock, (char *)p, len, 0);
		if(ret <= 0)
		{
			printf("cc send back Failed\n");
		}
		else
		{
			printf("cc send back %d\n", ret);
		}
		break;
	case STOP_SLAVE_FIN:
		break;
	case STOP_ALL_FIN:
		break;
	default:
		break;
	}

	return 0;
}


int cc_send_tgt_pkt(SOCKET sock, char *buf, int len)
{
	int ret = send(sock, buf, len, 0);
	if(ret <= 0)
	{
		printf("cc send tgt Failed\n");
	}
	else
	{
		printf("cc send tgt %d\n", ret);
	}

	return 0;
}

int cc_ctl_work(cc_proto_t *p, int len, thrd_cc_ctx_t *ctx)
{
	int ret;
	SOCKET new_sock = ctx->sock;

	if (cc_chk_pkt_hdr(p) < 0)
	{
		return -1;
	}

	switch (p->cmd)
	{
	case HEART_BEAT:
		break;
	case START_SLAVE:
		if (p->b_new && len >= sizeof(cc_proto_t))
		{
			int index = p->ctx.index;
			SOCKET tgt_sock = g_table[index].sock;
			//index = cc_find_tgt(ctx->ipv4, ctx->port, &tgt_sock);
			printf("find [%d] sock %d slave %s:%d->%s:%d\n", 
				index, tgt_sock,
				p->ctx.srv_ip, p->ctx.srv_port, p->ctx.tgt_ip, p->ctx.tgt_port);
			if (tgt_sock != INVALID_SOCKET)
			{
// 				while(g_table[index].unused == 0)
// 				{
// 					delay(1000);
// 				}
				cc_send_tgt_pkt(tgt_sock, (char *)p, len);
			}
			p->b_ret = 1;
		}
		break;
	case START_SLAVE_FIN:
		break;
	case STOP_SLAVE:
		break;
	case STOP_SLAVE_FIN:
		break;
	case STOP_ALL:
		if (p->b_stop)
		{
			g_cc_cfg.b_stop = 1;
		}

		if (p->b_exit)
		{
			g_cc_cfg.b_exit = 1;
		}
		break;
	default:
		break;
	}

	ret = send(new_sock, (char *)p, len, 0);
	if(ret <= 0)
	{
		printf("ctl send back Failed\n");
	}
	else
	{
		printf("ctl send back %d\n", ret);
	}

	return 0;
}


THREAD_RETURN thread_cc_client(void* para)
{
	SOCKET sock = INVALID_SOCKET;
	char buf[1024];
	char recv_buf[1024];
	char out[100];
	
	struct sockaddr_in sa;
	int sa_len = sizeof(struct sockaddr);
	thread_slave_ctx_t *ctx = (thread_slave_ctx_t *)malloc(sizeof(thread_slave_ctx_t));
	memcpy(ctx, para, sizeof(thread_slave_ctx_t));

	while(g_cc_cfg.b_exit == 0)
	{
		int ret = -1;
		unsigned int tms = 0;
		cc_proto_t *p;
		unsigned long ip1;

		//printf("cc client ready %d...\n", ctx->srv_port);
		ip1 = fwd_get_host(ctx->srv_ip);
		if(-1 == ip1)
		{
			xspf(out, sizeof(out),
				"[-]  Reslove Host %s Failed...\n", ctx->srv_ip);
			log_file(out, D_ERR, 0xff);
			delay(10 * 1000);
			continue;
		}

		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(sock == INVALID_SOCKET)
		{
			xspf(out, sizeof(out),
				"[-]  cc socket Failed...\n");
			log_file(out, D_ERR, 0xff);
			delay(10 * 1000);
			continue;
		}

		sa.sin_family = AF_INET;
		sa.sin_port = htons(ctx->srv_port);
		sa.sin_addr.s_addr = (ip1);

		// reconnect 3 times
		while (connect(sock, (struct sockaddr*)&sa, sa_len) != 0)
		{
			if (g_log_level)
			{
				xspf(out, sizeof(out),
					"[-]  Connect Failed,Try Again..\n");
				log_file(out, D_INFO, 0xff);
			}

			if (tms > 3)
			{
				break;
			}
			delay(1000);
			tms++;
		}

		if (tms > 3)
		{
			closesocket(sock);
			sock = INVALID_SOCKET;
			delay(200 * 1000);
			continue;
		}

		p = (cc_proto_t *)buf;
		p->flag = 0x55aa;
		p->ver = 0xff;
		p->cmd = HEART_BEAT;
		ret = send(sock, buf, sizeof(cc_proto_t), 0);
		if(ret <= 0)
		{
			if (g_log_level)
			{
				xspf(out, sizeof(out), "[-]  send Failed\n");
				log_file(out, D_INFO, 0xff);
			}
			closesocket(sock);
			sock = INVALID_SOCKET;
			continue;
		}
		else
		{
			printf("[+]  send %d\n", ret);
		}

		//set_recv_timeout(sock, 10);
		do 
		{
			ret = fwd_select_wait_timeout(sock, 6);
			if (ret > 0)
			{
				ret = recv(sock, recv_buf, 1024, 0);
				if(ret <= 0)
				{
					if (g_log_level)
					{
						xspf(out, sizeof(out), "[-]  recv Failed\n");
						log_file(out, D_INFO, 0xff);
					}
					closesocket(sock);
					sock = INVALID_SOCKET;
					break;
				}
				else
				{
					printf("[+]  recv len %d\n", ret);
					if (ret >= sizeof(cc_proto_t))
					{
						cc_client_work((cc_proto_t *)recv_buf, sock);
					}
				}
			} 
			else
			{
				if (ret != 0)
				{
					printf("something error1\n");
				}

				p = (cc_proto_t *)buf;
				p->flag = 0x55aa;
				p->ver = 0xff;
				p->cmd = HEART_BEAT;
				ret = sizeof(cc_proto_t);
				if(send(sock, buf, ret, 0) <= 0)
				{
					if (g_log_level)
					{
						xspf(out, sizeof(out), "[-]  send Failed\n");
						log_file(out, D_INFO, 0xff);
					}
					closesocket(sock);
					sock = INVALID_SOCKET;
					break;
				}
				else
				{
					printf("[+]  send %d\n", ret);
				}
			}

			delay(1000);

		} while (g_cc_cfg.b_exit == 0);

	}// End-while

	if (sock > 0)
	{
		closesocket(sock);
	}
	free(ctx);

	return 0;
}


int main_func(int argc,char**argv)
{
	int ret = -1;
	int32_t n = 2;
	char * addr1=NULL, *addr2=NULL;
	int32_t port1=0,port2=0;
	const char* command[] = {"-l", "-c", "-t", "-s", "-a", "-p", "-x"};
	int32_t i, cnt = sizeof(command) / sizeof(*command);

    if (argc < 2)
    {
        help(argv[0]);
        return 0;
    }

    for (i = 0; i < cnt; i++)
    {
        if (strcmp(command[i], argv[1]) == 0)
		{
            break;
		}
    }

	SOCKET_INIT

    switch (i)
    {
    case LISTEN_MODE:
		if (argc >= 4)
		{
			port1 = cfg_get_port(argv[n]);
			port2 = cfg_get_port(argv[++n]);
			if (port1 > 0 && port2 > 0)
			{
				fwd_listen((uint16_t)port1, (uint16_t)port2, 0);
			}
			ret = 0;
		}
		break;
	case CC_MODE:
        if (argc >= 2)
        {
			uint16_t ports[2] = {0};

			if (argc == 4)
			{
				port1 = cfg_get_port(argv[n]);
				port2 = cfg_get_port(argv[++n]);
				if (port1 > 0 && port2 > 0)
				{
					ports[0] = (uint16_t)port1;
					ports[1] = (uint16_t)port2;
				}
			}

			g_cc_cfg.cmd = CC_MODE;
			init_mutex();
			//in_create_thread(thread_cc_mode, ports, 1);
			fwd_cc_mode(ports);
			uninit_mutex();
			ret = 0;
        }
        break;

    case TRAN_MODE:
        if (argc >= 5)
        {
            port1 = cfg_get_port(argv[n]);
            addr2 = argv[++n];
            port2 = cfg_get_port(argv[++n]);
			if (port1 > 0 && port2 > 0)
			{
				fwd_tran((uint16_t)port1, addr2, (uint16_t)port2);
				ret = 0;
			}
        }
        break;
	case SLAVE_MODE:
		if (argc >= 6)
		{
			addr1 = argv[n];
			port1 = cfg_get_port(argv[++n]);
			addr2 = argv[++n];
			port2 = cfg_get_port(argv[++n]);
			if (port1 > 0 && port2 > 0 && port1 < 65534 && port2 < 65535)
			{
				fwd_slave(addr1, (uint16_t)port1, addr2, (uint16_t)port2);
				ret = 0;
			}
		}
		break;
	case ADV_SLAVE_MODE:
		if (argc >= 3)
		{
			addr1 = argv[n];
			if (argc == 4)
			{
				port1 = cfg_get_port(argv[++n]);
			}
			else
			{
				port1 = CC_PORT;
			}
			//printf("input %s:%d\n", addr1, port1);

			if (port1 > 0 && port1 < 65534)
			{
				thread_slave_ctx_t ctx = {0};
				
				g_cc_cfg.cmd = ADV_SLAVE_MODE;
				ctx.srv_port = (uint16_t)port1;
				xspf(ctx.srv_ip, sizeof(ctx.srv_ip), "%s", addr1);
				//printf("srv ip %s\n", ctx.srv_ip);
				in_create_thread(thread_cc_client, &ctx, 1);

				ret = 0;
			}
		}
		break;
    case PROXY_MODE:
		{
			uint16_t listen_port = DEFAULT_PROXY_PORT;

			if(argc > 2)
			{
				listen_port = (uint16_t)atoi(argv[2]);
			}

			if(argc == 5)
			{
				xspf(g_username, sizeof(g_username), "%s", argv[2]);
				xspf(g_password, sizeof(g_password), "%s", argv[3]);
			}

			init_mutex();
			fwd_proxy(listen_port);
			uninit_mutex();

			ret = 0;
		}
		break;
	case CTL_MODE:
		if (argc >= 6)
		{
			addr1 = argv[n];
			port1 = cfg_get_port(argv[++n]);
			addr2 = argv[++n];
			port2 = cfg_get_port(argv[++n]);
			if (port1 > 0 && port2 > 0 && port1 < 65534 && port2 < 65535)
			{
				fwd_ctl(addr1, (uint16_t)port1, addr2, (uint16_t)port2);
				ret = 0;
			}
		}
		break;
    default:
		break;
    }

	if (ret < 0)
	{
		help(argv[0]);
	}

	SOCKET_UNINIT

    return 0;
}

#define ARGC_MAXCOUNT 10

int main_func(int argc,char**argv);

void ctrl_c(int32_t i)
{
	fprintf(stdout,"[-] Receive(%d): Ctrl+C..I'll quit..\n", i);
	//   fprintf(stdout,"[+] Let me exit....\n");
	//   fprintf(stdout,"[+] All Right!\n\n");
	exit(0);
}

int main(int argc,char** argv)
{
	int ret;

#ifndef WIN32
	signal(SIGSEGV, sig_handler);
#endif
    signal(SIGINT,ctrl_c);
    ret = main_func(argc,argv);

#ifdef COMMAND_MODE
    while(1)
    {
        char input_buf[8192]= {0};
        char *argv_list[ARGC_MAXCOUNT]= {"portfwd"};
        printf(">");
        int argc_count = 1;
        int flag = 0;
        int i;
        for(i=0; i<8192; ++i)
        {
            input_buf[i] = getchar();
            if(input_buf[i] == '\n' || input_buf[i] == -1 )
            {
                input_buf[i] = '\0';
            }
            if(input_buf[i]=='\0' || argc_count>=ARGC_MAXCOUNT-2)
            {
                break;
            }
            if(flag ==0 && input_buf[i]!=' ' && input_buf[i]!='\0' )
            {
                flag = 1;
                argv_list[argc_count] = input_buf+i;
                ++argc_count;
            }
            else if(flag ==1 && (input_buf[i]==' ' || input_buf[i]=='\0') )
            {
                flag = 0;
                input_buf[i] = '\0';
            }
        }
        argv_list[argc_count] = NULL;
#ifdef portfwd_DEBUG
        putchar('\n');
        for(i=0; i<argc_count; ++i)
        {
            printf("argv[%d]: %s\n",i,argv_list[i]);
        }
#endif
        ret = main_func(argc_count,argv_list);
    }
#endif
    return ret;
}

int test (int argc,char** argv)
{
	int32_t n = 2;
	const char* logpath=NULL,*hexpath=NULL,*textpath=NULL;
	while (++n<argc)
	{
		if (strcmp(argv[n],"-hex")==0)
		{
			if (argc-1<++n)
			{
				fprintf(stdout,"[-] ERROR: -hex Must supply file name.\n\n");
				return 0;
			}
			hexpath = argv[n];
		}
		else if (strcmp(argv[n],"-text")==0)
		{
			if (argc-1<++n)
			{
				fprintf(stdout,"[-] ERROR: -text Must supply file name.\n\n");
				return 0;
			}
			textpath = argv[n];
		}
		else if (strcmp(argv[n],"-log")==0)
		{
			if (argc-1<++n)
			{
				fprintf(stdout,"[-] ERROR: -log Must supply file name.\n\n");
				return 0;
			}
			logpath = argv[n];
		}
		else
		{
			fprintf(stdout,"[-] ERROR:  %s  Undefined.\n\n",argv[n]);
			return 0;
		}
	}

	if (logpath)
	{
		cfg_set_file(&portfwd_log,logpath);
		if(portfwd_log==NULL)return 0;
	}
	if (hexpath)
	{
		cfg_set_file(&portfwd_hex,hexpath);
		if(portfwd_hex==NULL)return 0;
	}
	if (textpath)
	{
		cfg_set_file(&portfwd_text,textpath);
		if(portfwd_text==NULL)return 0;
	}

	return 0;
}
