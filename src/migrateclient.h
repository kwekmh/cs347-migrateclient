#ifndef MIGRATECLIENT_MIGRATECLIENT_H_
#define MIGRATECLIENT_MIGRATECLIENT_H_

#include <unordered_map>
#include <pthread.h>
#include <stdint.h>

#include "service.h"
#include "tcp_socket_options.h"

#define STR_VALUE(arg) #arg

#define DEFAULT_CLIENT_PORT 13500
#define MSG_BUFFER_SIZE 256
#define CLIENT_MAX_BUFFER_SIZE 256
#define LOCAL_DAEMON_DATA_DIRECTORY STR_VALUE(/var/migrateclient)
#define LOCAL_DAEMON_SOCKET_FILENAME STR_VALUE(local-socket)
#define LOCAL_DAEMON_MAX_CONNECTIONS 5000

typedef struct Context {
  std::unordered_map<int, Service *> services;
  pthread_mutex_t services_mutex;
  std::unordered_map<int, int> socks;
  std::unordered_map<int, bool> socks_ready;
  std::unordered_map<int, pthread_mutex_t *> sock_mutexes;
  std::unordered_map<int, pthread_cond_t *> sock_conds;
  pthread_mutex_t sock_mutexes_mutex;
  pthread_mutex_t sock_conds_mutex;
} Context;

typedef struct LocalClientStruct {
  Context *context;
  int socket;
} LocalClientStruct;

typedef struct ClientStruct {
  Context *context;
  int socket;
} ClientStruct;

void * StartDaemon(void *c);
void * StartLocalDaemon(void *c);
void * HandleClient(void *s);
void * HandleLocalClient(void *s);
int AwaitSocketMessage(int sock);
void SendSocketRequest(Context *context, int service_identifier);
bool RepairSocket(int fd, int service_identifier, std::string ip_address, uint32_t send_seq, uint32_t recv_seq, TcpSocketOptions &sock_opts);
bool TcpRepairOn(int fd);
bool TcpRepairOff(int fd);
uint32_t GetSequenceNumber(int sock, int q_id);
pthread_mutex_t * GetMutex(Context *context, int service_identifier);
pthread_cond_t * GetCond(Context *context, int service_identifier);
void InitDaemon(Context *context);

#endif
