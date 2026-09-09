#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <ldap.h>

#include <system_error>

namespace boost_openldap {

class connection {
public:
    connection(boost::asio::io_context& io, const char* uri);
    ~connection();

    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    LDAP* native_handle() const noexcept { return ldap_; }

    // Returns a duplicated descriptor suitable for Asio monitoring.
    // libldap retains ownership of its original descriptor.
    boost::asio::posix::stream_descriptor& descriptor() noexcept { return descriptor_; }

    std::error_code initialize();

private:
    boost::asio::io_context& io_;
    LDAP* ldap_ = nullptr;
    boost::asio::posix::stream_descriptor descriptor_;
};

} // namespace boost_openldap
