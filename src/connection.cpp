#include "boost_openldap/connection.hpp"

#include <boost/asio/error.hpp>

#include <cerrno>
#include <cstring>
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
        return;
    }

    int version = LDAP_VERSION3;
    if (ldap_set_option(ldap_, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ldap_, nullptr, nullptr);
        ldap_ = nullptr;
        return;
    }
}

connection::~connection()
{
    descriptor_.close();
    if (ldap_) {
        ldap_unbind_ext_s(ldap_, nullptr, nullptr);
    }
}

std::error_code connection::initialize()
{
    if (!ldap_) {
        return make_error_code(errc::invalid_handle);
    }

    int fd = -1;
    const int rc = ldap_get_option(ldap_, LDAP_OPT_DESC, &fd);
    if (rc != LDAP_OPT_SUCCESS || fd < 0) {
        return make_error_code(errc::ldap_error);
    }

#ifndef _WIN32
    // Never give libldap's descriptor directly to Asio: stream_descriptor
    // assumes ownership and may close it. Monitor a duplicated descriptor
    // instead; both descriptors refer to the same underlying socket.
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
    // POSIX stream_descriptor is intentionally used in the first milestone.
    return make_error_code(errc::ldap_error);
#endif
}

} // namespace boost_openldap
