#include "logger.hpp"

/**
 * Initialize logger.
 */
void initLogger() {
  // New attributes that hold filename and line number
  logging::core::get()->add_global_attribute(
      "File", attrs::mutable_constant<std::string>(""));
  logging::core::get()->add_global_attribute("Line",
                                             attrs::mutable_constant<int>(0));

  // A console log with severity, filename, line and message
  logging::add_console_log(
      std::clog,
      keywords::format =
          (expr::stream << "<" << boost::log::trivial::severity << "> " << '['
                        << expr::attr<std::string>("File") << ':'
                        << expr::attr<int>("Line") << "] " << expr::smessage));
  logging::add_common_attributes();
}

/**
 * Convert filepath.
 */
std::string path_to_filename(std::string path) {
  return path.substr(path.find_last_of("/\\") + 1);
}
