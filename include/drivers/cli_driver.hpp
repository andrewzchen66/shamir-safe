#pragma once

#include <cstdlib>
#include <string>
#include <sys/ioctl.h>

class CLIDriver {
public:
  CLIDriver();
  void init();
  void clear();
  void print_info(std::string message);
  void print_success(std::string message);
  void print_warning(std::string message);
  void print_left(std::string message);
  void print_right(std::string message);

private:
  struct winsize size;
};
