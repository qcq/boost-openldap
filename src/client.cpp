#include "boost_openldap/client.hpp"
#include "boost_openldap/error.hpp"

#include <ldap.h>

#include <memory>
#include <string>
#include <utility>

namespace boost_openldap {

namespace {

class boost_openldap_category final : public std::error_category {
public:
    const char* name() const noexcept override { return "boost-openldap"; }

    std::string message(int value) const override
    {
        switch (static_cast<errc>(value)) {
        case errc::invalid_handle: return "invalid LDAP handle";
        case errc::ldap_error: return "LDAP operation error";
        case errc::operation_cancelled: return "LDAP operation cancelled";
        case errc::operation_timeout: return "LDAP operation timeout";
        case errc::connection_in_progress: return "LDAP connection in progress";
        }
        return "unknown boost-openldap error";
    }
};

class openldap_category final : public std::error_category {
public:
    const char* name() const noexcept override { return "openldap"; }

    std::string message(int value) const override
    {
        return ldap_err2string(value);
    }
};

const boost_openldap_category boost_openldap_category_instance{};
const openldap_category openldap_category_instance{};

} // namespace

const std::error_category& error_category() noexcept
{
    return boost_openldap_category_instance;
}

const std::error_category& ldap_error_category() noexcept
{
    return openldap_category_instance;
}

std::error_code make_error_code(errc e) noexcept
{
    return {static_cast<int>(e), error_category()};
}

std::error_code make_ldap_error(int value) noexcept
{
    return {value, ldap_error_category()};
}

client::client(boost::asio::io_context& io, std::string uri)
    : impl_(std::make_unique<implementation>(io, std::move(uri)))
{
}

client::~client() = default;

} // namespace boost_openldap
