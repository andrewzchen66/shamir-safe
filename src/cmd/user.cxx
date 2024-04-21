#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/pkg/user.hpp"

/*
 * Usage: ./auth_user <json config file path>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 2)) {
    std::cout << "Usage: ./auth_user <config file>" << std::endl;
    return 1;
  }

  // Initialize drivers
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create client object and run
  UserConfig user_config = load_user_config(argv[1]);
  UserClient user = UserClient(network_driver, crypto_driver, user_config);
  user.run();
  return 0;
}
