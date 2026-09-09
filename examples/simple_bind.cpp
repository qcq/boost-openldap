#include <boost_openldap.hpp>

#include <boost/asio/io_context.hpp>

#include <iostream>
#include <utility>

int main()
{
    boost::asio::io_context io;

    boost_openldap::client client(io, "ldap://127.0.0.1:389");

    boost_openldap::bind_request request{
        "cn=admin,dc=example,dc=com",
        "password"};

    client.async_bind(
        std::move(request),
        [](std::error_code ec, boost_openldap::bind_result result) {
            if (ec) {
                std::cerr << "bind failed: " << ec.message() << '\n';
                return;
            }

            std::cout << "bind succeeded, LDAP result = "
                      << result.ldap_result << '\n';
        });

    io.run();
}
