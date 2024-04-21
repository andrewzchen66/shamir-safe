#include <cmath>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <term.h>
#include <unistd.h>

#include "../../include-shared/colors.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include/drivers/cli_driver.hpp"

/**
 * Constructor.
 */
CLIDriver::CLIDriver() {}

/**
 * Starts up the CLI.
 */
void CLIDriver::init() { ioctl(STDOUT_FILENO, TIOCGWINSZ, &size); }

/**
 * Print a new info message on the left side of the screen.
 * @param message Message to print.
 */
void CLIDriver::print_info(std::string message) {
  std::cout << DIM << message << RESET << std::endl;
}

/**
 * Print a new success message on the left side of the screen.
 * @param message Message to print.
 */
void CLIDriver::print_success(std::string message) {
  std::cout << GREEN << message << RESET << std::endl;
}

/**
 * Print a new warning message on the left side of the screen.
 * @param message Message to print.
 */
void CLIDriver::print_warning(std::string message) {
  std::cout << RED << message << RESET << std::endl;
}

/**
 * Print a new message on the left side of the screen.
 * @param message Message to print.
 */
void CLIDriver::print_left(std::string message) {
  std::cout << "\r" << LINE_CLEAR << GREEN << message << RESET << std::endl;
  std::cout << "> " << std::flush;
}

/**
 * Print a new message on the right side of the screen.
 * @param message Message to print.
 */
void CLIDriver::print_right(std::string message) {
  // Want to erase input
  int moveUps = message.length() / this->size.ws_col + 1;
  for (int i = 0; i < moveUps; i++) {
    std::cout << LINE_UP;
  }

  // Print input back to user flush to right
  std::cout << LINE_CLEAR << std::right << std::setw(this->size.ws_col)
            << message << std::endl;
  std::cout << "> ";
}

/**
 * Clears the REPL screen.
 */
void CLIDriver::clear() {
  if (!cur_term) {
    int result;
    setupterm(NULL, STDOUT_FILENO, &result);
    if (result <= 0)
      return;
  }
  putp(tigetstr("clear"));
}
