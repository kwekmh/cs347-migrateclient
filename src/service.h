#ifndef MIGRATECLIENT_SERVICE_H_
#define MIGRATECLIENT_SERVICE_H_

class Service {
  int m_service_identifier;
  int m_socket;
  int m_fd;

public:
  Service(int service_identifier, int socket);
  void SetServiceIdentifier(int service_identifier);
  int GetServiceIdentifier();
  void SetSocket(int socket);
  int GetSocket();
  void SetDescriptor(int fd);
  int GetDescriptor();
};

#endif
