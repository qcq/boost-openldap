#include "boost_openldap/client.hpp"
#include "boost_openldap/error.hpp"

#include <boost/asio/post.hpp>

#include <ldap.h>

#include <memory>
#include <string>
#include <utility>

namespace boost_openldap {

namespace {

class ldap_category final : public std::error_category {
public:
    const char* name() const noexcept override { return "boost-openldap"; }

    std::string message(int value) const override
    {
        if (value > 0) {
            return ldap_err2string(value);
        }

        switch (static_cast<errc>(value)) {
        case errc::invalid_handle: return "invalid LDAP handle";
        case errc::ldap_error: return "LDAP operation error";
        case errc::operation_cancelled: return "LDAP operation cancelled";
        case errc::operation_timeout: return "LDAP operation timeout";
        }
        return "unknown boost-openldap error";
    }
};

const ldap_category category_instance{};

} // namespace

const std::error_category& error_category() noexcept
{
    return category_instance;
}

std::error_code make_error_code(errc e) noexcept
{
    return {static_cast<int>(e), error_category()};
}

struct client::implementation {
    implementation(boost::asio::io_context& io, std::string uri)
        : connection(io, uri.c_str())
    {
    }

    connection connection;

    template <typename Handler>
    void async_bind(bind_request request, Handler&& handler)
    {
        // The operation implementation is added in the next milestone.
        // Keeping completion asynchronous here is important: callers must
        // never have to handle an inline completion unexpectedly.
        boost::asio::post(
            connection.descriptor().get_executor(),
            [handler = std::forward<Handler>(handler)]() mutable {
                handler(make_error_code(errc::ldap_error), {});
            });
    }
};

client::client(boost::asio::io_context& io, std::string uri)
    : impl_(std::make_unique<implementation>(io, std::move(uri)))
{
}

client::~client() = default;

} // namespace boost_openldap
