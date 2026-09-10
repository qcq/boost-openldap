cmake_minimum_required(VERSION 3.20)

project(boost-openldap
    VERSION 0.1.0
    DESCRIPTION "Asynchronous LDAP client for C++ based on Boost.Asio and OpenLDAP"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED COMPONENTS system)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDAP REQUIRED IMPORTED_TARGET ldap)

add_library(boost_openldap
    src/client.cpp
    src/connection.cpp
    src/operation.cpp)

target_include_directories(boost_openldap
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(boost_openldap
    PUBLIC
        Boost::system
        PkgConfig::LDAP)

target_compile_features(boost_openldap PUBLIC cxx_std_20)

target_compile_options(boost_openldap PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)

add_executable(simple_bind examples/simple_bind.cpp)
target_link_libraries(simple_bind PRIVATE boost_openldap)

include(CTest)
if(BUILD_TESTING)
    add_executable(test_async_bind tests/test_async_bind.cpp)
    target_link_libraries(test_async_bind PRIVATE boost_openldap)
    add_test(NAME async_bind COMMAND test_async_bind)

    add_executable(test_real_ldap tests/test_real_ldap.cpp)
    target_link_libraries(test_real_ldap PRIVATE boost_openldap)
endif()

include(GNUInstallDirs)

install(TARGETS boost_openldap
    EXPORT boost-openldap-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
