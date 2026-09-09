#include "boost_openldap/connection.hpp"
#include "boost_openldap/error.hpp"

#include <cerrno>
#include <system_error>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace boost_openldap {

connection::connection(boost::asio::io_context& io, const char* uri)
    : io_(io), descriptor_(io)
{
    const int rc = ldap_initialize(&ldap_, uri);
    if (rc != LDAP_SUCCESS) {
        ldap_ = nullptr;
        initialization_error_ = make_ldap_error(rc);
        return;
    }

    int version = LDAP_VERSION3;
    if (ldap_set_option(ldap_, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ldap_, nullptr, nullptr);
        ldap_ = nullptr;
        initialization_error_ = make_error_code(errc::ldap_error);
        return;
    }

#ifdef LDAP_OPT_CONNECT_ASYNC
    int async_connect = LDAP_OPT_ON;
    if (ldap_set_option(ldap_, LDAP_OPT_CONNECT_ASYNC, &async_connect) != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ldap_, nullptr, nullptr);
        ldap_ = nullptr;
        initialization_error_ = make_error_code(errc::ldap_error);
        return;
    }
#endif

    // OpenLDAP uses the network timeout while polling an asynchronous connect.
    // A short default keeps a failed connection from blocking indefinitely.
    struct timeval network_timeout {30, 0};
    ldap_set_option(ldap_, LDAP_OPT_NETWORK_TIMEOUT, &network_timeout);
}

connection::~connection()
{
    descriptor_.close();
    if (ldap_) {
        ldap_unbind_ext_s(ldap_, nullptr, nullptr);
    }
}

std::error_code connection::ensure_connected()
{
    if (initialization_error_) {
        return initialization_error_;
    }
    if (!ldap_) {
        return make_error_code(errc::invalid_handle);
    }
    if (descriptor_.is_open()) {
        return {};
    }

    const int rc = ldap_connect(ldap_, nullptr);
    if (rc == LDAP_SUCCESS) {
        return attach_descriptor();
    }

    if (rc == LDAP_X_CONNECTING) {
        const auto ec = attach_descriptor();
        if (ec) {
            return ec;
        }
        return make_error_code(errc::connection_in_progress);
    }

    return make_ldap_error(rc);
}

std::error_code connection::finish_connect()
{
    if (!ldap_) {
        return make_error_code(errc::invalid_handle);
    }

    const int rc = ldap_connect(ldap_, nullptr);
    if (rc == LDAP_SUCCESS) {
        return {};
    }
    if (rc == LDAP_X_CONNECTING) {
        return make_error_code(errc::connection_in_progress);
    }
    return make_ldap_error(rc);
}

std::error_code connection::attach_descriptor()
{
    if (descriptor_.is_open()) {
        return {};
    }

    int fd = -1;
    const int rc = ldap_get_option(ldap_, LDAP_OPT_DESC, &fd);
    if (rc != LDAP_OPT_SUCCESS || fd < 0) {
        return make_error_code(errc::ldap_error);
    }

#ifndef _WIN32
    // libldap owns the original descriptor. Asio monitors a duplicate so
    // that closing stream_descriptor never closes libldap's socket.
    const int monitored_fd = ::dup(fd);
    if (monitored_fd < 0) {
        return std::error_code(errno, std::generic_category());
    }

    boost::system::error_code ec;
    descriptor_.assign(monitored_fd, ec);
    if (ec) {
        ::close(monitored_fd);
        return std::error_code(ec.value(), std::system_category());
    }
    return {};
#else
    return make_error_code(errc::ldap_error);
#endif
}

} // namespace boost_openldap
