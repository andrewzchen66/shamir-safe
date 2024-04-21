
if(NOT "/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitinfo.txt" IS_NEWER_THAN "/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: '/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E remove_directory "/home/cs1515-user/final-ps-wd/build/_deps/doctest-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/home/cs1515-user/final-ps-wd/build/_deps/doctest-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"  clone --no-checkout "https://github.com/onqtam/doctest" "doctest-src"
    WORKING_DIRECTORY "/home/cs1515-user/final-ps-wd/build/_deps"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/onqtam/doctest'")
endif()

execute_process(
  COMMAND "/usr/bin/git"  checkout v2.4.11 --
  WORKING_DIRECTORY "/home/cs1515-user/final-ps-wd/build/_deps/doctest-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'v2.4.11'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git"  submodule update --recursive --init 
    WORKING_DIRECTORY "/home/cs1515-user/final-ps-wd/build/_deps/doctest-src"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/home/cs1515-user/final-ps-wd/build/_deps/doctest-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitinfo.txt"
    "/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/home/cs1515-user/final-ps-wd/build/_deps/doctest-subbuild/doctest-populate-prefix/src/doctest-populate-stamp/doctest-populate-gitclone-lastrun.txt'")
endif()

