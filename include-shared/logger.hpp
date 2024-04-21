/*
Usage:
    init();
    src::severity_logger<logging::trivial::severity_level> lg;
    CUSTOM_LOG(lg, debug) << "A regular message";

Possible severity levels (defined in trivial.hpp):
    trace
    debug
    info
    warning
    error
    fatal
*/

#pragma once

#include <string>

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/attributes/mutable_constant.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>

namespace logging = boost::log;
namespace attrs = boost::log::attributes;
namespace expr = boost::log::expressions;
namespace src = boost::log::sources;
namespace keywords = boost::log::keywords;

// Macro that includes severity, filename and line number
#define CUSTOM_LOG(logger, sev)                                                \
  BOOST_LOG_STREAM_WITH_PARAMS(                                                \
      (logger),                                                                \
      (set_get_attrib("File", path_to_filename(__FILE__)))(                    \
          set_get_attrib("Line", __LINE__))(::boost::log::keywords::severity = \
                                                (boost::log::trivial::sev)))

// Set attribute and return the new value
template <typename ValueType>
ValueType set_get_attrib(const char *name, ValueType value) {
  auto attr = logging::attribute_cast<attrs::mutable_constant<ValueType>>(
      logging::core::get()->get_global_attributes()[name]);
  attr.set(value);
  return attr.get();
}

// Functions
void initLogger();
std::string path_to_filename(std::string path);
