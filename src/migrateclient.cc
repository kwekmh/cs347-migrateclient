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
#include "tcp_socket_options.h"

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

        pthread_mutex_t *mutex = GetMutex(context, service_identifier);
        pthread_cond_t *cond = GetCond(context, service_identifier);

        int old_sock;

        pthread_mutex_lock(mutex);
        old_sock = context->socks[service_identifier];
        pthread_mutex_unlock(mutex);

        uint32_t send_seq = GetSequenceNumber(old_sock, TCP_SEND_QUEUE);
        uint32_t recv_seq = GetSequenceNumber(old_sock, TCP_RECV_QUEUE);

        TcpSocketOptions sock_opts(old_sock);

        std::cout << "Old socket info: " << sock_opts.GetString() << std::endl;

        int new_sock;

        context->socks_ready[service_identifier] = false;
        // Send socket request to local service

        std::cout << "Sending socket request" << std::endl;
        SendSocketRequest(context, service_identifier);

        pthread_mutex_lock(mutex);

        while (!context->socks_ready[service_identifier]) {
          pthread_cond_wait(cond, mutex);
        }

        context->socks_ready[service_identifier] = false;
        new_sock = context->socks[service_identifier];

        pthread_mutex_unlock(mutex);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(ip_address.c_str());
        addr.sin_port = htons(service_identifier);
        if (connect(new_sock, (sockaddr *) &addr, sizeof(addr)) < 0) {
          perror("Migration connect");
        }
        //RepairSocket(old_sock, service_identifier, ip_address, send_seq, recv_seq, sock_opts);

        /*
        TcpSocketOptions new_opts(new_sock);

        std::cout << "New socket options: " << new_opts.GetString() << std::endl;
        */
        /*
        auto it = context->services.find(service_identifier);
        if (it != context->services.end()) {
          int fd = it->second->GetDescriptor();
          RepairSocket(fd, service_identifier, ip_address);
        } else {
          std::cout << "Service not found!" << std::endl;
        }
        */
      }
    }
  }
  return NULL;
}

void SendSocketRequest(Context *context, int service_identifier) {
  auto it = context->services.find(service_identifier);
  if (it != context->services.end()) {
    std::cout << "Sending socket request to " << service_identifier << std::endl;
    Service *service = it->second;
    int sock = service->GetSocket();
    std::stringstream msgstream;

    msgstream << "SOCKET";

    std::string msg = msgstream.str();

    msgstream.str("");
    msgstream.clear();

    msgstream << msg.length() << " " << msg;

    msg = msgstream.str();

    if (send(sock, msg.c_str(), msg.length(), 0) < 0) {
      perror("SendSocketRequest() send");
    }
  } else {
    std::cout << "Service not found" << std::endl;
  }
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
        pthread_mutex_t *mutex = GetMutex(context, service_identifier);
        pthread_cond_t *cond = GetCond(context, service_identifier);
        pthread_mutex_lock(mutex);
        context->socks[service_identifier] = fd;
        context->socks_ready[service_identifier] = true;
        pthread_cond_signal(cond);
        pthread_mutex_unlock(mutex);
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

bool RepairSocket(int fd, int service_identifier, std::string ip_address, uint32_t send_seq, uint32_t recv_seq, TcpSocketOptions &sock_opts) {
  std::cout << "Repairing socket: " << fd << " " << service_identifier << " " << ip_address << std::endl;

  int aux_sendq = TCP_SEND_QUEUE;
  int aux_recvq = TCP_RECV_QUEUE;

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

  setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &aux_sendq, sizeof(aux_sendq));
  setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &send_seq, sizeof(send_seq));
  setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &aux_recvq, sizeof(aux_recvq));
  setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &recv_seq, sizeof(recv_seq));

  uint32_t mss_clamp = sock_opts.GetMssClamp();
  uint32_t snd_wscale = sock_opts.GetSndWscale();
  uint32_t rcv_wscale = sock_opts.GetRcvWscale();
  uint32_t timestamp = sock_opts.GetTimestamp();

  struct tcp_repair_opt opts[4];

  // SACK
  opts[0].opt_code = TCPOPT_SACK_PERMITTED;
  opts[0].opt_val = 0;

  // Window scales
  opts[1].opt_code = TCPOPT_WINDOW;
  opts[1].opt_val = snd_wscale + (rcv_wscale << 16);

  // Timestamps
  opts[2].opt_code = TCPOPT_TIMESTAMP;
  opts[2].opt_val = 0;

  // MSS clamp
  opts[3].opt_code = TCPOPT_MAXSEG;
  opts[3].opt_val = mss_clamp;

  setsockopt(fd, SOL_TCP, TCP_REPAIR_OPTIONS, opts, 4 * sizeof(struct tcp_repair_opt));

  setsockopt(fd, SOL_TCP, TCP_TIMESTAMP, &timestamp, sizeof(timestamp));

  ret = TcpRepairOff(fd);

  if (ret < 0) {
    perror("RepairSocket() setsockopt off");
    return false;
  }

  // START OF DEBUG CODE
  sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);

  getpeername(fd, (sockaddr *) &peer_addr, &peer_addr_len);

  char new_ip_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(peer_addr.sin_addr), new_ip_str, INET_ADDRSTRLEN);

  std::cout << "New peer address: " << new_ip_str << std::endl;
  // END OF DEBUG CODE

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

uint32_t GetSequenceNumber(int sock, int q_id) {
  int aux_on = 1;
  int aux_off = 0;

  uint32_t seq_number;

  socklen_t seq_number_len = sizeof(seq_number);

  setsockopt(sock, SOL_TCP, TCP_REPAIR, &aux_on, sizeof(aux_on));

  setsockopt(sock, SOL_TCP, TCP_REPAIR_QUEUE, &q_id, sizeof(q_id));

  getsockopt(sock, SOL_TCP, TCP_QUEUE_SEQ, &seq_number, &seq_number_len);

  setsockopt(sock, SOL_TCP, TCP_REPAIR, &aux_off, sizeof(aux_off));

  return seq_number;
}

pthread_mutex_t * GetMutex(Context *context, int service_identifier) {
  pthread_mutex_t *mutex_ptr;
  pthread_mutex_lock(&context->sock_mutexes_mutex);
  auto it = context->sock_mutexes.find(service_identifier);

  if (it != context->sock_mutexes.end()) {
    mutex_ptr = it->second;
  } else {
    mutex_ptr = new pthread_mutex_t;
    pthread_mutex_init(mutex_ptr, NULL);
    context->sock_mutexes[service_identifier] = mutex_ptr;
  }
  pthread_mutex_unlock(&context->sock_mutexes_mutex);
  return mutex_ptr;
}

pthread_cond_t * GetCond(Context *context, int service_identifier) {
  pthread_cond_t *cond_ptr;
  pthread_mutex_lock(&context->sock_conds_mutex);
  auto it = context->sock_conds.find(service_identifier);

  if (it != context->sock_conds.end()) {
    cond_ptr = it->second;
  } else {
    cond_ptr = new pthread_cond_t;
    pthread_cond_init(cond_ptr, NULL);
    context->sock_conds[service_identifier] = cond_ptr;
  }
  pthread_mutex_unlock(&context->sock_conds_mutex);

  return cond_ptr;
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
  pthread_mutex_init(&context->sock_mutexes_mutex, NULL);
  pthread_mutex_init(&context->sock_conds_mutex, NULL);
  InitDaemon(context);
}
