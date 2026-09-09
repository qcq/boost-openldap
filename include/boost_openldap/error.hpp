#pragma once

#include <system_error>
#include <type_traits>

namespace boost_openldap {

enum class errc {
    invalid_handle = -1,
    ldap_error = -2,
    operation_cancelled = -3,
    operation_timeout = -4,
    connection_in_progress = -5,
};

const std::error_category& error_category() noexcept;
const std::error_category& ldap_error_category() noexcept;

std::error_code make_error_code(errc e) noexcept;
std::error_code make_ldap_error(int value) noexcept;

} // namespace boost_openldap

namespace std {
template <>
struct is_error_code_enum<boost_openldap::errc> : true_type {};
} // namespace std
