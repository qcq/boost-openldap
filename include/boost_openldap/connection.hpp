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
    boost::asio::any_io_executor executor() const noexcept { return descriptor_.get_executor(); }

    // libldap owns its descriptor. Asio monitors a duplicated descriptor.
    boost::asio::posix::stream_descriptor& descriptor() noexcept { return descriptor_; }

    // Starts the libldap connection and prepares the descriptor for Asio.
    std::error_code ensure_connected();

private:
    boost::asio::io_context& io_;
    LDAP* ldap_ = nullptr;
    boost::asio::posix::stream_descriptor descriptor_;
    std::error_code initialization_error_;
};

} // namespace boost_openldap
