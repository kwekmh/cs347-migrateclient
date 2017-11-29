#ifndef MIGRATECLIENT_MIGRATECLIENT_H_
#define MIGRATECLIENT_MIGRATECLIENT_H_

#include <unordered_map>
#include <pthread.h>

#include "service.h"

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
bool RepairSocket(int fd, int service_identifier, std::string ip_address);
bool TcpRepairOn(int fd);
bool TcpRepairOff(int fd);
void InitDaemon(Context *context);

#endif
