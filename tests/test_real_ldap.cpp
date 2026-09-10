#include <boost_openldap.hpp>
#include <boost/asio/io_context.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    const std::string uri = argc > 1 ? argv[1] : "ldap://127.0.0.1:1389";

    boost::asio::io_context io;
    boost_openldap::client client(io, uri);

    bool bind_ok = false;
    bool search_ok = false;
    bool failed = false;

    client.async_bind(
        {"cn=admin,dc=example,dc=com", "secret"},
        [&](std::error_code ec, boost_openldap::bind_result result) {
            if (ec) {
                std::cerr << "real LDAP bind failed: " << ec.category().name()
                          << ':' << ec.value() << ' ' << ec.message() << '\n';
                failed = true;
                return;
            }

            if (result.ldap_result != 0) {
                std::cerr << "real LDAP bind returned " << result.ldap_result << '\n';
                failed = true;
                return;
            }

            bind_ok = true;

            boost_openldap::search_request request{
                "dc=example,dc=com",
                boost_openldap::search_scope::subtree,
                "(objectClass=inetOrgPerson)",
                {"cn", "mail"}};

            client.async_search(
                std::move(request),
                [&](std::error_code search_ec, boost_openldap::search_result result) {
                    if (search_ec) {
                        std::cerr << "real LDAP search failed: " << search_ec.category().name()
                                  << ':' << search_ec.value() << ' ' << search_ec.message() << '\n';
                        failed = true;
                        return;
                    }

                    if (result.ldap_result != 0 || result.entries.size() != 1) {
                        std::cerr << "unexpected search result: ldap_result="
                                  << result.ldap_result << " entries=" << result.entries.size() << '\n';
                        failed = true;
                        return;
                    }

                    const auto& entry = result.entries.front();
                    if (entry.dn != "cn=alice,dc=example,dc=com") {
                        std::cerr << "unexpected DN: " << entry.dn << '\n';
                        failed = true;
                        return;
                    }

                    bool found_cn = false;
                    bool found_mail = false;
                    for (const auto& attribute : entry.attributes) {
                        if (attribute.name == "cn" && attribute.values.size() == 1 &&
                            attribute.values.front() == "alice") {
                            found_cn = true;
                        }
                        if (attribute.name == "mail" && attribute.values.size() == 1 &&
                            attribute.values.front() == "alice@example.com") {
                            found_mail = true;
                        }
                    }

                    if (!found_cn || !found_mail) {
                        std::cerr << "expected cn/mail attributes were not returned\n";
                        failed = true;
                        return;
                    }

                    search_ok = true;
                });
        });

    io.run();

    if (failed || !bind_ok || !search_ok) {
        return EXIT_FAILURE;
    }

    std::cout << "real LDAP integration test passed\n";
    return EXIT_SUCCESS;
}
