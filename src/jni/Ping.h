#pragma once

#include "RawSocket.h"

#ifdef __cplusplus
extern "C" {
#endif

const int TIMEOUT_RETURN_CODE = -1;
const int ERROR_RETURN_CODE = -2;
const int SEND_ERROR_RETURN_CODE = -3;
const int RECEIVE_ERROR_RETURN_CODE = -4;
const int NOT_PERMITED_ERROR_RETURN_CODE = -5;

const int LOG_LEVEL_TRACE = 0;
const int LOG_LEVEL_DEBUG = 1;
const int LOG_LEVEL_WARN = 2;

typedef struct pr
{
	jfloat rtt;
	jint ttl;
} PingResult;

static void writeToJavaLog(JNIEnv *env, const jint level, const char *format, ...);
static void getAddr(JNIEnv *env, jbyteArray address, char *addr);

static PingResult doPing(JNIEnv *env, jclass cls, jbyteArray address, jlong timeout, jint dataSize);

JNIEXPORT float JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1pingHost
(JNIEnv *env, jclass cls, jbyteArray address, jlong timeout, jint datasize, jintArray ttl);

#if !defined(_WIN32)
typedef struct node
{
	int id;
	int seq;
	int status;
	float rtt;
	float ttl;
	int timeout;

	pthread_cond_t *lock;

	struct node *next;
} taskNode;

void tvsub(register struct timeval *out, register struct timeval *in);
u_short in_cksum(u_short *addr, int len);
void pinger(int ident, int seq, int datalen, int s, char *hostname, int timing, struct sockaddr whereto);
int getSequence();

static void *threadFunc(void *arg);

void addPingTask(taskNode ** head, int id, int seq, int timeout, pthread_cond_t *lock);
PingResult removePingTask(taskNode ** head, int id, int seq);

int getRtt(u_char *buf, int cc, struct timeval tv);
void findTaskAndSetResult(void *buf, int bytes, struct timeval tv);
#else
typedef struct PingData {
  char *addr;
  jlong timeout;
  jint dataSize;
  PingResult pr;
  HANDLE setPriorityEvt;
} PINGDATA, *PPINGDATA;

DWORD WINAPI pingThreadFunction(LPVOID lpParam);
void fillSendData(std::unique_ptr<char[]> &sendData, jint dataSize);
#endif // defined

JNIEXPORT jint JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingStartup
(JNIEnv *env, jclass cls);

JNIEXPORT void JNICALL
Java_com_savarese_rocksaw_net_RawSocket__1_1PingShutdown
(JNIEnv *env, jclass cls);

#ifdef __cplusplus
}
#endif


