#pragma once
#include <cstring>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include "../../include-shared/messages.hpp"

class NetworkDriver {
public:
  virtual void listen(int port) = 0;
  virtual void connect(std::string address, int port) = 0;
  virtual void disconnect() = 0;
  virtual void send(std::vector<unsigned char> data) = 0;
  virtual std::vector<unsigned char> read() = 0;
  virtual std::string get_remote_info() = 0;
};

class NetworkDriverImpl : public NetworkDriver {
public:
  NetworkDriverImpl();
  void listen(int port);
  void connect(std::string address, int port);
  void disconnect();
  void send(std::vector<unsigned char> data);
  std::vector<unsigned char> read();
  std::string get_remote_info();

private:
  int port;
  boost::asio::io_context io_context;
  std::shared_ptr<boost::asio::ip::tcp::socket> socket;
};
