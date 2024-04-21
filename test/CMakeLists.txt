cmake_minimum_required(VERSION 3.14)

# List all files containing tests. (Change as needed)
if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
    set(TESTFILES network_driver.cxx testing_helpers.cxx test_provided.cxx test.cxx)
else()
    set(TESTFILES test_provided.cxx)
endif()

set(TEST_MAIN unit_tests)   # Default name for test executable (change if you wish).
set(TEST_RUNNER_PARAMS " --reporters=xml")  # Any arguemnts to feed the test runner (change as needed).

# --------------------------------------------------------------------------------
#                         Make Tests (no change needed).
# --------------------------------------------------------------------------------

add_executable(${TEST_MAIN} ${TESTFILES})

if ( "$ENV{CS1515_TA_MODE}" STREQUAL "on" )
    target_link_libraries(${TEST_MAIN} PRIVATE ${LIBRARY_NAME} ${LIBRARY_NAME_SHARED} ${LIBRARY_NAME_TA} doctest)
else()
    target_link_libraries(${TEST_MAIN} PRIVATE ${LIBRARY_NAME} ${LIBRARY_NAME_SHARED} doctest)
endif()

set_target_properties(${TEST_MAIN} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(${TEST_MAIN} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS YES
)
