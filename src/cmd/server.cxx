#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

using namespace boost::asio::ip;

/*
 * Usage: ./auth_server <port> <json config file path>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 3)) {
    std::cout << "Usage: ./auth_server <port> <config file>" << std::endl;
    return 1;
  }
  int port = std::stoi(argv[1]);

  // Create server object and run
  ServerConfig server_config = load_server_config(argv[2]);
  ServerClient server = ServerClient(server_config);
  server.run(port);
  return 0;
}
