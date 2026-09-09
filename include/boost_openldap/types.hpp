#pragma once

#include <string>

namespace boost_openldap {

struct bind_request {
    std::string dn;
    std::string password;
};

struct bind_result {
    int ldap_result = 0;
};

} // namespace boost_openldap
