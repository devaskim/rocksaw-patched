#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <memory>

#else

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define	MAXWAIT		10	/* max time to wait for response, sec. */
#define	MAXPACKET	4096	/* max packet size */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

#endif

#include <errno.h>
#include "Ping.h"

static void writeToJavaLog(JNIEnv *env, const jint level, const char *format, ...)
{
  char msgBuf[150];

  va_list args;
  va_start(args, format);

  vsprintf(msgBuf, format, args);

  jclass clazz = env->FindClass("com/tibbo/linkserver/util/ping/Ping");

  if (clazz != 0)
  {
    jmethodID writeToLogMethod = env->GetStaticMethodID(clazz, "writeToLog", "(Ljava/lang/String;I)V");
    if (writeToLogMethod != 0)
    {
      jstring jstr = env->NewStringUTF(msgBuf);
      env->CallStaticVoidMethod(clazz, writeToLogMethod, jstr, level);
    }
  }

  va_end(args);
}

static void writeToFileLog(const char *format, ...)
{
  va_list args;
  va_start(args, format);

  FILE *f = fopen("c:\\ping_log.txt", "a");
  if (f == NULL)
  {
    return;
  }

  fprintf(f, format, args);

  fclose(f);

  va_end(args);
}

static void getAddr(JNIEnv *env, jbyteArray address, char *addr)
{
	jbyte *buf = env->GetByteArrayElements(address, NULL);
	jint addrLen = env->GetArrayLength(address);

	int i;
	for(i = 0; i < addrLen; i++)
	{
		char str[15];

		if (i < addrLen - 1)
			sprintf(str, "%d.", (unsigned char)(buf[i]));
		else
			sprintf(str, "%d", (unsigned char)(buf[i]));

		if (i == 0)
			strcpy(addr, str);
		else
			strcat(addr, str);
	}

    env->ReleaseByteArrayElements(address, buf, JNI_ABORT);
}

//--------------------------------------------------------------------------------------------------------------------------------------

JNIEXPORT float JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1pingHost
(JNIEnv *env, jclass cls, jbyteArray address, jlong timeout, jint datasize, jintArray ttl)
{
  PingResult res;
  res.rtt = ERROR_RETURN_CODE;

  if (env->GetArrayLength(address) == 0)
	{
		return ERROR_RETURN_CODE;
	}

	res = doPing(env, cls, address, timeout, datasize);

	jint aTtl[] = { res.ttl };
	env->SetIntArrayRegion(ttl, 0, 1, aTtl);

	return res.rtt;
}

//--------------------------------------------------------------------------------------------------------------------------------------

#if defined(_WIN32)

struct IcmpFileDeleter
{
  typedef HANDLE pointer;

  void operator()(HANDLE h)
  {
    if (h != INVALID_HANDLE_VALUE)
    {
      IcmpCloseHandle(h);
    }
  }
};

static PingResult doPing(JNIEnv *env, jclass cls, jbyteArray address, jlong timeout, jint dataSize)
{
  PingResult pingResult;
  pingResult.ttl = 0;
  pingResult.rtt = 0;

  PPINGDATA pingData = (PPINGDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PINGDATA));
  if (pingData == NULL)
  {
    writeToJavaLog(env, LOG_LEVEL_WARN, "Unable to allocate system memory for thread");
    
    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    return pingResult;
  }

  char addr[100];
  getAddr(env, address, addr);

  HANDLE setPriorityEvt = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (setPriorityEvt == NULL)
  {
    writeToJavaLog(env, LOG_LEVEL_WARN, "Unable to create wait for priority set event");

    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    return pingResult;
  }
  
  pingData->addr = addr;
  pingData->timeout = timeout;
  pingData->dataSize = dataSize;
  pingData->setPriorityEvt = setPriorityEvt;

  pingData->pr.rtt = pingResult.rtt;
  pingData->pr.ttl = pingResult.ttl;

  DWORD threadId;
  HANDLE threadHandle = CreateThread(
    NULL,               // default security attributes
    0,                  // use default stack size  
    pingThreadFunction, // thread function name
    pingData,           // argument to thread function 
    0,                  // use default creation flags 
    &threadId);         // returns the thread identifier 

  if (threadHandle == NULL)
  {
    writeToJavaLog(env, LOG_LEVEL_WARN, "Unable to create thread");
    
    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    return pingResult;
  }
  else
  {
    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Created thread %d", threadId);
  }

  if (!SetThreadPriority(threadHandle, THREAD_PRIORITY_HIGHEST))
  {
    writeToJavaLog(env, LOG_LEVEL_WARN, "Unable to set high priority for thread %d", threadId);
  }
  SetEvent(setPriorityEvt);

  if (WaitForSingleObject(threadHandle, timeout + 2000) == WAIT_OBJECT_0)
  {
    pingResult.rtt = pingData->pr.rtt;
    pingResult.ttl = pingData->pr.ttl;

    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Ping done for thread %d", threadId);
  }
  else
  {
    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Waiting for thread failed due to timeout");

    pingResult.rtt = RECEIVE_ERROR_RETURN_CODE;
  }

  CloseHandle(threadHandle);
  CloseHandle(setPriorityEvt);

  HeapFree(GetProcessHeap(), 0, pingData);
  pingData = NULL;

  writeToJavaLog(env, LOG_LEVEL_DEBUG, "[%s] Roundtrip time = %f milliseconds. Ttl = %ld. Thread = %d", addr, pingResult.rtt, pingResult.ttl, threadId);

  return pingResult;
}

DWORD WINAPI pingThreadFunction(LPVOID lpParam)
{
  PPINGDATA pingData = (PPINGDATA)lpParam;

  PingResult pingResult;
  pingResult.ttl = 0;
  pingResult.rtt = 0;

  char *addr = pingData->addr;
  jlong timeout = pingData->timeout;
  jint dataSize = pingData->dataSize;

  //Waiting for SetThreadPriority is done
  WaitForSingleObject(pingData->setPriorityEvt, timeout + 1000);

  unsigned long ipaddr = INADDR_NONE;

  std::unique_ptr<char[]> sendData(new char[dataSize]());
  fillSendData(sendData, dataSize);
  
  LPVOID replyBuffer = NULL;
  DWORD replySize = 0;

  ipaddr = inet_addr(addr);

  std::unique_ptr<HANDLE, IcmpFileDeleter> icmpFile(IcmpCreateFile());
  if (icmpFile.get() == INVALID_HANDLE_VALUE)
  {
    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    pingData->pr.rtt = pingResult.rtt;
    return 0;
  }

  replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
  replyBuffer = (VOID *)malloc(replySize);
  if (replyBuffer == NULL)
  {
    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    pingData->pr.rtt = pingResult.rtt;
    return 0;
  }

  HANDLE waitEvt = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (waitEvt == NULL)
  {
    pingResult.rtt = SEND_ERROR_RETURN_CODE;
    pingData->pr.rtt = pingResult.rtt;
    return 0;
  }

  IcmpSendEcho2(icmpFile.get(), waitEvt, NULL, NULL, ipaddr, sendData.get(), sizeof(sendData.get()), NULL,
    replyBuffer, replySize, timeout);

  if (WaitForSingleObject(waitEvt, timeout + 1000) == WAIT_OBJECT_0)
  {
    IcmpParseReplies(replyBuffer, replySize);

    PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
    struct in_addr replyAddr;
    replyAddr.S_un.S_addr = echoReply->Address;

    switch (echoReply->Status)
    {
      case IP_DEST_HOST_UNREACHABLE:
        pingResult.rtt = RECEIVE_ERROR_RETURN_CODE;
        break;
      case IP_DEST_NET_UNREACHABLE:
        pingResult.rtt = RECEIVE_ERROR_RETURN_CODE;
        break;
      case IP_REQ_TIMED_OUT:
        pingResult.rtt = RECEIVE_ERROR_RETURN_CODE;
        break;
      default:
        pingResult.rtt = echoReply->RoundTripTime;
        pingResult.ttl = echoReply->Options.Ttl;
        break;
    }

    CloseHandle(waitEvt);
  }
  else
  {
    pingResult.rtt = RECEIVE_ERROR_RETURN_CODE;
  }

  pingData->pr.rtt = pingResult.rtt;
  pingData->pr.ttl = pingResult.ttl;

  free(replyBuffer);
  replyBuffer = NULL;

  return 0;
}

void fillSendData(std::unique_ptr<char[]> &sendData, jint dataSize)
{
  const char startCh = 'a';
  const char stopCh = 'z';
  const byte alphabetLen = stopCh - startCh + 1;

  for (int i = 0; i < dataSize; i++)
  {
    sendData[i] = startCh + (i % alphabetLen);
  }
}

JNIEXPORT jint JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingStartup
(JNIEnv *env, jclass cls)
{
    return 0;
}

JNIEXPORT void JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingShutdown
(JNIEnv *env, jclass cls)
{
    return;
}

#else
//--------------------------------------------------------------------------------------------------------------------------------------

pthread_t thread;

pthread_mutex_t listLock;

pthread_mutex_t countLock;

int gSequence = 0;

taskNode * pingTasks = NULL;


JNIEXPORT jint JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingStartup
(JNIEnv *env, jclass cls)
{
    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Starting ping: creating mutex");

	if (pthread_mutex_init(&listLock, NULL) != 0)
	{
		return -1;
	}

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "Starting ping: mutex was successfully created");

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "Starting ping: creating thread");

	if (pthread_create(&thread, NULL, threadFunc, NULL) != 0)
	{
		return -1;
	}

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "Starting ping: thread was successfully created");

	return 0;
}

JNIEXPORT void JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingShutdown
(JNIEnv *env, jclass cls)
{
    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Stopping ping: stopping thread");

	pthread_cancel(thread);
	pthread_join(thread, NULL);

    writeToJavaLog(env, LOG_LEVEL_DEBUG, "Stopping ping: thread was successfully stopped");

	taskNode * current = pingTasks;
	while (current != NULL)
	{
		int id = current->id;
		int seq = current->seq;

		current = current->next;

		removePingTask(&pingTasks, id, seq);
	}

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "Stopping ping: all tasks were successfully removed");

	pthread_mutex_destroy(&listLock);

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "Stopping ping: mutex was successfully destroyed");

	return;
}

//--------------------------------------------------------------------------------------------------------------------------------------

taskNode* task_node_new(int id, int seq, int timeout, pthread_cond_t *lock)
{
	taskNode *node = (taskNode*)malloc(sizeof(taskNode));

	node->id = id;
	node->seq = seq;
	node->status = 0;
	node->rtt = TIMEOUT_RETURN_CODE;
	node->ttl = 0;
	node->timeout = timeout;
	node->lock = lock;
	node->next = NULL;

	return node;
}

void addPingTask(taskNode ** head, int id, int seq, int timeout, pthread_cond_t *lock)
{
	pthread_mutex_lock(&listLock);

	if (*head == NULL)
	{
		*head = task_node_new(id, seq, timeout, lock);
	}
	else
	{
		taskNode* current = *head;
		while (current->next != NULL)
		{
			current = current->next;
		}

		current->next = task_node_new(id, seq, timeout, lock);
	}

	pthread_mutex_unlock(&listLock);
}

PingResult removePingTask(taskNode ** head, int id, int seq)
{
	pthread_mutex_lock(&listLock);

	PingResult pingResult;
	pingResult.rtt = -1;
	pingResult.ttl = 0;

	taskNode * current = *head;
	taskNode * tempNode = NULL;

	while (current != NULL)
	{
		if ((current->id) == id && (current->seq) == seq)
		{
			if(tempNode == NULL)
			{
				*head = current->next;
			}
			else
			{
				tempNode->next = current->next;
			}

			pingResult.rtt = current->rtt;
			pingResult.ttl = current->ttl;
			free(current);

			break;
		}

		tempNode = current;
		current = current->next;
	}

	pthread_mutex_unlock(&listLock);

	return pingResult;
}

//--------------------------------------------------------------------------------------------------------------------------------------

int getRtt(u_char *buf, int cc, struct timeval tv)
{
	struct ip *ip;
	register struct icmp *icp;
	struct timeval *tp;
	int hlen, triptime;

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN)
	{
		return -1;
	}

	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
	if (icp->icmp_type != ICMP_ECHOREPLY)
	{
		return -1;
	}

	tp = (struct timeval *)&icp->icmp_data[0];
	tvsub(&tv, tp);
	triptime = tv.tv_sec * 1000 + (tv.tv_usec / 1000);

	return triptime;
}

void findTaskAndSetResult(void *buf, int bytes, struct timeval tv)
{
	int rtt = getRtt((u_char *)buf, bytes, tv);

	struct iphdr *ip = (struct iphdr *)buf;
	struct icmphdr *icmp = (struct icmphdr *)(buf+ip->ihl*4);

    pthread_mutex_lock(&listLock);

	taskNode * current = pingTasks;
	while (current != NULL)
	{
		if ((current->status == 0) && (current->id == icmp->un.echo.id) && (current->seq == icmp->un.echo.sequence) && (icmp->type == 0))
		{
			current->rtt = rtt;
			current->ttl = ip->ttl;
			current->status = 1;

			pthread_cond_signal(current->lock);

			break;
		}

		current = current->next;
	}

    pthread_mutex_unlock(&listLock);
}

static void *threadFunc(void *arg)
{
	int sd;
	struct sockaddr_in addr;
	u_char buf[MAXPACKET];

	struct protoent *proto;
	if ((proto = getprotobyname("icmp")) == NULL)
	{
		return NULL;
	}

	sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if ( sd < 0 )
	{
		return NULL;
	}

	int bytes = 0;
	socklen_t len = sizeof(addr);

	struct timeval tv;

	while(1)
	{
		bzero(buf, sizeof(buf));

		bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &len);

		if ( bytes > 0 )
		{
			gettimeofday(&tv, NULL);
			findTaskAndSetResult(buf, bytes, tv);
		}
	}

	return NULL;
}

//--------------------------------------------------------------------------------------------------------------------------------------

/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 * Modified at Uc Berkeley
 *
 * Changed argument to inet_ntoa() to be struct in_addr instead of u_long
 * DFM BRL 1992
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 *
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */


/*
* sequence # for outbound packets = #sent
*/
int getSequence()
{
	pthread_mutex_lock(&countLock);
	gSequence ++;
	if (gSequence == 0 || gSequence > 0xffff)
	{
		gSequence = 1;
	}
	pthread_mutex_unlock(&countLock);
	return gSequence;
}

static PingResult doPing(JNIEnv *env, jclass cls, jbyteArray address, jlong timeout, jint dataSize)
{
	PingResult pingResult;
	pingResult.ttl = 0;
	pingResult.rtt = ERROR_RETURN_CODE;

	int ident = getpid() & 0xFFFF;
	int seq = getSequence();

	char host[100];
	getAddr(env, address, host);

	struct sockaddr whereto;/* Who to ping */
	struct sockaddr_in *to = (struct sockaddr_in *) &whereto;
	struct protoent *proto;

	char *hostname;
	char hnamebuf[MAXHOSTNAMELEN];

	bzero((char *)&whereto, sizeof(struct sockaddr));
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(host);
	if (to->sin_addr.s_addr != (unsigned)-1)
	{
		strcpy(hnamebuf, host);
		hostname = hnamebuf;
	}
	else
	{
		struct hostent *hp;	/* Pointer to host info */
		hp = gethostbyname(host);
		if (hp)
		{
			to->sin_family = hp->h_addrtype;
			bcopy(hp->h_addr, (caddr_t)&to->sin_addr, hp->h_length);
			hostname = hp->h_name;
		}
		else
		{
			writeToJavaLog(env, LOG_LEVEL_DEBUG, "%s unknown host", host);

			pingResult.rtt = ERROR_RETURN_CODE;
			return pingResult;
		}
	}

	int datalen;		/* How much data */
	if (dataSize > 0)
		datalen = dataSize;
	else
		datalen = 64 - 8;
	if (datalen > MAXPACKET)
	{
		writeToJavaLog(env, LOG_LEVEL_DEBUG, "%s packet size too large", host);

		pingResult.rtt = ERROR_RETURN_CODE;
		return pingResult;
	}
	int timing = 0;
	if (datalen >= sizeof(struct timeval))	/* can we time 'em? */
		timing = 1;

	if ((proto = getprotobyname("icmp")) == NULL)
	{
		writeToJavaLog(env, LOG_LEVEL_DEBUG, "%s unknown protocol", host);

		pingResult.rtt = ERROR_RETURN_CODE;
		return pingResult;
	}

	int s;/* Socket file descriptor */
	if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0)
	{
		writeToJavaLog(env, LOG_LEVEL_DEBUG, "%s can't open socket", host);

		pingResult.rtt = ERROR_RETURN_CODE;
		return pingResult;
	}

	pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cnd = PTHREAD_COND_INITIALIZER;

	pthread_mutex_lock(&mtx);

	addPingTask(&pingTasks, ident, seq, timeout, &cnd);
	pinger(ident, seq, datalen, s, hostname, timing, whereto); /* start things going */

	struct timeval now;
	gettimeofday(&now, NULL);

	long delta_usec = now.tv_usec + timeout*1000;
	long secToWait  = now.tv_sec + delta_usec/1000000;
	long usecToWait = delta_usec%1000000;

	struct timespec timeToWait;
	timeToWait.tv_sec  = secToWait;
	timeToWait.tv_nsec = usecToWait*1000;

	pthread_cond_timedwait(&cnd, &mtx, &timeToWait);

	pingResult = removePingTask(&pingTasks, ident, seq);

	pthread_mutex_unlock(&mtx);

	writeToJavaLog(env, LOG_LEVEL_DEBUG, "%s Received. Roundtrip time = %f milliseconds. Ttl = %d. Seq = %d",
		host, pingResult.rtt, pingResult.ttl, seq);

	close(s);

	return pingResult;
}

/*
* 			P I N G E R
*
* Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
* will be added on by the kernel.  The ID field is our UNIX process ID,
* and the sequence number is an ascending integer.  The first 8 bytes
* of the data portion are used to hold a UNIX "timeval" struct in VAX
* byte-order, to compute the round-trip time.
*/
void pinger(int ident, int seq, int datalen, int s, char *hostname, int timing, struct sockaddr whereto)
{
	static u_char outpack[MAXPACKET];
	register struct icmp *icp = (struct icmp *) outpack;
	int i, cc;
	register struct timeval *tp = (struct timeval *) &outpack[8];
	register u_char *datap = &outpack[8 + sizeof(struct timeval)];

	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = seq;
	icp->icmp_id = ident;		/* ID */

	cc = datalen + 8;			/* skips ICMP portion */

	struct timezone tz;         /* leftover */
	if (timing)
		gettimeofday(tp, &tz);

	for (i = 8; i<datalen; i++)	/* skip 8 for time */
		*datap++ = i;

	/* Compute ICMP checksum here */
	icp->icmp_cksum = in_cksum((u_short *)icp, cc);

	sendto(s, outpack, cc, 0, &whereto, sizeof(struct sockaddr));
}


/*
*			I N _ C K S U M
*
* Checksum routine for Internet Protocol family headers (C Version)
*
*/
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	*  Our algorithm is simple, using a 32 bit accumulator (sum),
	*  we add sequential 16 bit words to it, and at the end, fold
	*  back all the carry bits from the top 16 bits into the lower
	*  16 bits.
	*/
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		u_short	u = 0;

		*(u_char *)(&u) = *(u_char *)w;
		sum += u;
	}

	/*
	* add back carry outs from top 16 bits to low 16 bits
	*/
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
* 			T V S U B
*
* Subtract 2 timeval structs:  out = out - in.
*
* Out is assumed to be >= in.
*/
void tvsub(register struct timeval *out, register struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}
#endif
