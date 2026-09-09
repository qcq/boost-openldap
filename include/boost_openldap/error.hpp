#pragma once

#include <system_error>

namespace boost_openldap {

enum class errc {
    invalid_handle = 1,
    ldap_error,
    operation_cancelled,
    operation_timeout,
};

const std::error_category& error_category() noexcept;

std::error_code make_error_code(errc e) noexcept;

} // namespace boost_openldap

namespace std {
template <>
struct is_error_code_enum<boost_openldap::errc> : true_type {};
} // namespace std
