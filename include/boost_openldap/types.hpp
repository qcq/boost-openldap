#pragma once

#include <string>
#include <vector>

namespace boost_openldap {

struct bind_request {
    std::string dn;
    std::string password;
};

struct bind_result {
    int ldap_result = 0;
};

enum class search_scope {
    base = 0,
    one_level = 1,
    subtree = 2,
};

struct search_request {
    std::string base_dn;
    std::string filter = "(objectClass=*)";
    search_scope scope = search_scope::subtree;
    std::vector<std::string> attributes;
};

struct search_attribute {
    std::string name;
    std::vector<std::string> values;
};

struct search_entry {
    std::string dn;
    std::vector<search_attribute> attributes;
};

struct search_result {
    int ldap_result = 0;
    std::vector<search_entry> entries;
};

} // namespace boost_openldap
