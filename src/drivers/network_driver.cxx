#include <stdexcept>
#include <vector>

#include "../../include/drivers/network_driver.hpp"

using namespace boost::asio;
using ip::tcp;

/**
 * Constructor. Sets up IO context and socket.
 */
NetworkDriverImpl::NetworkDriverImpl() : io_context() {
  this->socket = std::make_shared<tcp::socket>(io_context);
}

/**
 * Listen on the given port at localhost.
 * @param port Port to listen on.
 */
void NetworkDriverImpl::listen(int port) {
  tcp::acceptor acceptor(this->io_context, tcp::endpoint(tcp::v4(), port));
  acceptor.accept(*this->socket);
}

/**
 * Connect to the given address and port.
 * @param address Address to connect to.
 * @param port Port to conect to.
 */
void NetworkDriverImpl::connect(std::string address, int port) {
  if (address == "localhost")
    address = "127.0.0.1";
  this->socket->connect(
      tcp::endpoint(boost::asio::ip::address::from_string(address), port));
}

/**
 * Disconnect graceefully.
 */
void NetworkDriverImpl::disconnect() {
  this->socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
  this->socket->close();
  this->io_context.stop();
}

/**
 * Sends a fixed amount of data by sending length first.
 * @param data Bytes of data to send.
 */
void NetworkDriverImpl::send(std::vector<unsigned char> data) {
  int length = htonl(data.size());
  boost::asio::write(*this->socket, boost::asio::buffer(&length, sizeof(int)));
  boost::asio::write(*this->socket, boost::asio::buffer(data));
}

/**
 * Receives a fixed amount of data by receiving length first.
 * @return std::vector<unsigned char> data read.
 * @throws error when eof.
 */
std::vector<unsigned char> NetworkDriverImpl::read() {
  // read length
  int length;
  boost::system::error_code error;
  boost::asio::read(*this->socket, boost::asio::buffer(&length, sizeof(int)),
                    boost::asio::transfer_exactly(sizeof(int)), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  length = ntohl(length);

  // read message
  std::vector<unsigned char> data;
  data.resize(length);
  boost::asio::read(*this->socket, boost::asio::buffer(data),
                    boost::asio::transfer_exactly(length), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  return data;
}

/**
 * Get socket info as string.
 */
std::string NetworkDriverImpl::get_remote_info() {
  return this->socket->remote_endpoint().address().to_string() + ":" +
         std::to_string(this->socket->remote_endpoint().port());
}
