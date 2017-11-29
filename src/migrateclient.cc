#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string>
#include <iostream>
#include <pthread.h>
#include <cstring>
#include <sstream>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "migrateclient.h"

void * StartDaemon(void *c) {
  Context *context = (Context *) c;

  struct sockaddr_in addr;

  int sock;

  struct sockaddr_in client_addr;

  socklen_t client_addrlen;

  int client_sock;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("HandleDaemon() sock");
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(DEFAULT_CLIENT_PORT);

  if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    perror("HandleDaemon() bind");
  }

  listen(sock, 5);

  while (1) {
    client_addrlen = sizeof(client_addr);
    client_sock = accept(sock, (struct sockaddr *) &client_addr, &client_addrlen);

    pthread_t *client_thread = new pthread_t;

    ClientStruct *client_struct = new ClientStruct();
    client_struct->context = context;
    client_struct->socket = client_sock;

    pthread_create(client_thread, NULL, HandleClient, (void *) client_struct);
  }

  return NULL;
}

void * StartLocalDaemon(void *c) {
  Context *context = (Context *) c;
  struct stat stat_info;

  if (stat(LOCAL_DAEMON_DATA_DIRECTORY, &stat_info) != 0) {
    mkdir(LOCAL_DAEMON_DATA_DIRECTORY, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  }

  std::stringstream data_dir_ss;

  data_dir_ss << LOCAL_DAEMON_DATA_DIRECTORY;

  data_dir_ss.seekg(-1, std::ios::end);

  char last_char;

  data_dir_ss >> last_char;

  if (last_char != '/') {
    data_dir_ss << '/';
  }

  std::string data_dir = data_dir_ss.str();

  std::stringstream socket_ss;

  socket_ss << data_dir << LOCAL_DAEMON_SOCKET_FILENAME;

  std::string socket_file = socket_ss.str();

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);

  struct sockaddr_un addr, remote;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_file.c_str(), sizeof(addr.sun_path));

  unlink(socket_file.c_str());

  if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    perror("StartLocalDaemon() bind");
    exit(1);
  }

  if (listen(sock, LOCAL_DAEMON_MAX_CONNECTIONS) < 0) {
    perror("StartLocalDaemon() listen");
    exit(1);
  }

  while (1) {
    int new_sock;
    sockaddr_un *remote_ptr = new sockaddr_un;
    socklen_t addrlen = sizeof(remote);

    if ((new_sock = accept(sock, (struct sockaddr *) remote_ptr, &addrlen)) < 0) {
      perror("StartLocalDaemon() accept");
    }

    pthread_t client_pthread;

    LocalClientStruct *client_struct = new LocalClientStruct;

    client_struct->socket = new_sock;
    client_struct->context = context;

    pthread_create(&client_pthread, NULL, HandleLocalClient, (void *) client_struct);
  }
}

void * HandleClient(void *s) {
  ClientStruct *client_struct = (ClientStruct *) s;
  Context *context = client_struct->context;

  int in_bytes;

  char buf[CLIENT_MAX_BUFFER_SIZE];

  while (1) {
    in_bytes = recv(client_struct->socket, buf, MSG_BUFFER_SIZE, 0);
    if (in_bytes < 0) {
      perror("HandleClient() recv");
      // TODO: Clean up
      pthread_exit(NULL);
    } else if (in_bytes == 0) {
      // TODO: Clean up
      pthread_exit(NULL);
    }

    std::cout << "MSG: " << std::string(buf, in_bytes) << std::endl;

    int i = 0;

    while (i < in_bytes) {
      std::stringstream msg_size_ss;
      for (; i < in_bytes; i++) {
        if (buf[i] != ' ') {
          msg_size_ss << buf[i];
        } else {
          break;
        }
      }

      i++;

      std::string msg_size_str = msg_size_ss.str();
      int msg_size = std::stoi(msg_size_ss.str());
      std::cout << "Processing message of size " << msg_size << std::endl;
      if (msg_size > 6 && strncmp(buf + i, "MIGRATE", 7) == 0) {
        std::stringstream ip_address_ss;
        std::stringstream service_ident_ss;

        int max_bytes = i + msg_size;

        for (i += 8; i < max_bytes; i++) {
          if (buf[i] != ' ') {
            ip_address_ss << buf[i];
          } else {
            break;
          }
        }

        i++;

        for (; i < max_bytes; i++) {
          service_ident_ss << buf[i];
        }

        std::string ip_address = ip_address_ss.str();
        int service_identifier = std::stoi(service_ident_ss.str());

        auto it = context->services.find(service_identifier);
        if (it != context->services.end()) {
          int fd = it->second->GetDescriptor();
          RepairSocket(fd, service_identifier, ip_address);
        } else {
          std::cout << "Service not found!" << std::endl;
        }
      }
    }
  }
  return NULL;
}

void * HandleLocalClient(void *s) {
  LocalClientStruct *client_struct = (LocalClientStruct *) s;
  Context *context = client_struct->context;

  char buf[MSG_BUFFER_SIZE];

  int in_bytes;

  while (1) {
    in_bytes = recv(client_struct->socket, buf, MSG_BUFFER_SIZE, 0);
    if (in_bytes < 0) {
      perror("HandleLocalClient() recv");
      // TODO: Clean up
      pthread_exit(NULL);
    } else if (in_bytes == 0) {
      // TODO: Clean up
      pthread_exit(NULL);
    }

    std::cout << "LOCALMSG: " << std::string(buf, in_bytes) << std::endl;

    int i = 0;

    while (i < in_bytes) {
      std::stringstream msg_size_ss;
      for (; i < in_bytes; i++) {
        if (buf[i] != ' ') {
          msg_size_ss << buf[i];
        } else {
          break;
        }
      }

      i++;

      std::string msg_size_str = msg_size_ss.str();
      int msg_size = std::stoi(msg_size_ss.str());
      std::cout << "Processing message of size " << msg_size << std::endl;
      if (msg_size > 3 && strncmp(buf + i, "REG", 3) == 0) {
        std::stringstream service_ident_ss;
        int max_bytes = i + msg_size;

        for (i += 4; i < max_bytes; i++) {
          service_ident_ss << buf[i];
        }

        int service_identifier = std::stoi(service_ident_ss.str());

        Service *service;

        pthread_mutex_lock(&context->services_mutex);
        auto it = context->services.find(service_identifier);
        if (it == context->services.end()) {
          service = new Service(service_identifier, client_struct->socket);
          context->services[service_identifier] = service;
        } else {
          service = it->second;
          service->SetSocket(client_struct->socket);
        }
        pthread_mutex_unlock(&context->services_mutex);
      } else if (msg_size > 6 && strncmp(buf + i, "SOCKET", 6) == 0) {
        std::stringstream service_ident_ss;
        int max_bytes = i + msg_size;

        for (i += 7; i < max_bytes; i++) {
          service_ident_ss << buf[i];
        }

        int service_identifier = std::stoi(service_ident_ss.str());

        std::cout << "Receiving socket for " << service_identifier << std::endl;
        int fd = AwaitSocketMessage(client_struct->socket);
        std::cout << "Received socket " << fd << " for " << service_identifier << std::endl;

        Service *service;
        pthread_mutex_lock(&context->services_mutex);
        auto it = context->services.find(service_identifier);
        if (it == context->services.end()) {
          service = new Service(service_identifier, client_struct->socket);
          context->services[service_identifier] = service;
        } else {
          service = it->second;
        }
        service->SetDescriptor(fd);
        pthread_mutex_unlock(&context->services_mutex);
      }
    }
  }
  return NULL;
}

int AwaitSocketMessage(int sock) {
  std::cout << "Awaiting descriptor on " << sock << std::endl;
  struct {
    struct cmsghdr h;
    int fd[1];
  } buf;

  struct msghdr msghdr;
  char nothing;
  struct iovec nothing_ptr;
  struct cmsghdr *cmsghdr;

  int fd;

  nothing_ptr.iov_base = &nothing;
  nothing_ptr.iov_len = 1;

  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  msghdr.msg_iov = &nothing_ptr;
  msghdr.msg_iovlen = 1;
  msghdr.msg_flags = 0;
  msghdr.msg_control = &buf;
  msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int);
  cmsghdr = CMSG_FIRSTHDR(&msghdr);
  cmsghdr->cmsg_len = msghdr.msg_controllen;
  cmsghdr->cmsg_level = SOL_SOCKET;
  cmsghdr->cmsg_type = SCM_RIGHTS;

  ((int *) CMSG_DATA(cmsghdr))[0] = -1;

  if (recvmsg(sock, &msghdr, 0) < 0) {
    perror("AwaitSocketMessage() recvmsg");
    return -1;
  }

  std::cout << "Received socket descriptor" << std::endl;

  fd = ((int *) CMSG_DATA(cmsghdr))[0];

  return fd;
}

bool RepairSocket(int fd, int service_identifier, std::string ip_address) {
  std::cout << "Repairing socket: " << fd << " " << service_identifier << " " << ip_address << std::endl;

  int ret = TcpRepairOn(fd);

  if (ret < 0) {
    perror("RepairSocket() setsockopt on");
    return false;
  }

  sockaddr_in addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(service_identifier);
  addr.sin_addr.s_addr = inet_addr(ip_address.c_str());


  connect(fd, (sockaddr *) &addr, sizeof(addr));

  ret = TcpRepairOff(fd);

  if (ret < 0) {
    perror("RepairSocket() setsockopt off");
    return false;
  }

  std::cout << "Socket repaired" << std::endl;
  return true;
}

bool TcpRepairOn(int fd) {
  int aux = 1;
  if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux)) < 0) {
    perror("TcpRepairOn");
    return false;
  } else {
    return true;
  }
}

bool TcpRepairOff(int fd) {
  int aux = 0;
  if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux)) < 0) {
    perror("TcpRepairOff");
    return false;
  } else {
    return true;
  }
}

void InitDaemon(Context *context) {
  pthread_t daemon_pthread;
  pthread_t local_daemon_pthread;

  pthread_create(&daemon_pthread, NULL, StartDaemon, (void *) context);
  pthread_create(&local_daemon_pthread, NULL, StartLocalDaemon, (void *) context);

  pthread_join(daemon_pthread, NULL);
  pthread_join(local_daemon_pthread, NULL);
}

int main() {
  Context *context = new Context();
  pthread_mutex_init(&context->services_mutex, NULL);
  InitDaemon(context);
}
