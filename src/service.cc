#include "service.h"

Service::Service(int service_identifier, int socket) {
  this->m_service_identifier = service_identifier;
  this->m_socket = socket;
}

void Service::SetServiceIdentifier(int service_identifier) {
  this->m_service_identifier = service_identifier;
}

int Service::GetServiceIdentifier() {
  return this->m_service_identifier;
}

void Service::SetSocket(int socket) {
  this->m_socket = socket;
}

int Service::GetSocket() {
  return this->m_socket;
}

void Service::SetDescriptor(int fd) {
  this->m_fd = fd;
}

int Service::GetDescriptor() {
  return this->m_fd;
}
