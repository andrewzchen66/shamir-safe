#include "../../include/drivers/repl_driver.hpp"
#include "../../include-shared/colors.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/cli_driver.hpp"

const int FUNC_NAME_SIZE = 20;

/**
 * Constructor.
 */
template <class T> REPLDriver<T>::REPLDriver(T *owner) { this->owner = owner; }

/**
 * Add a new action to the repl.
 */
template <class T>
void REPLDriver<T>::add_action(std::string trigger, std::string guide,
                               void (T::*func)(std::string line)) {
  this->actions[trigger] = func;
  this->guides[trigger] = guide;
}

/**
 * Loop while listening for commands.
 */
template <class T> void REPLDriver<T>::run() {
  this->cli_driver->print_info("Type your command:");
  std::string message;
  while (std::getline(std::cin, message)) {
    try {
      std::vector<std::string> message_split = string_split(message, ' ');
      if (message_split.size() == 0) {
        continue;
      } else if (this->actions.count(message_split[0])) {
        ((this->owner)->*(this->actions[message_split[0]]))(message);
      } else if (message_split[0] == "exit") {
        break;
      } else {
        this->cli_driver->print_info("Command not found. Available commands: ");
        std::string finalStr;
        for (auto const &x : this->guides) {
          std::string lineStr;
          lineStr += x.first;
          lineStr.insert(lineStr.end(), FUNC_NAME_SIZE - lineStr.size(), ' ');
          lineStr += "- " + x.second;
          finalStr += lineStr + "\n";
        }
        std::cout << DIM << finalStr << RESET;
      }
      this->cli_driver->print_info("Type your command:");
    } catch (std::runtime_error &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}
