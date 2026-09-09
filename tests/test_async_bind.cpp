#include <boost_openldap.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

class fake_ldap_server {
public:
    fake_ldap_server(asio::io_context& io, int result_code)
        : acceptor_(io, tcp::endpoint(tcp::v4(), 0)),
          result_code_(result_code)
    {
    }

    unsigned short port() const
    {
        return acceptor_.local_endpoint().port();
    }

    void start()
    {
        acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
            if (ec) {
                error_ = ec;
                return;
            }
            socket_ = std::move(socket);
            socket_->async_read_some(
                asio::buffer(request_buffer_),
                [this](const boost::system::error_code& read_ec, std::size_t) {
                    if (read_ec) {
                        error_ = read_ec;
                        return;
                    }
                    send_bind_response();
                });
        });
    }

    boost::system::error_code error() const { return error_; }

private:
    void send_bind_response()
    {
        // LDAPMessage:
        //   SEQUENCE { messageID=1, bindResponse(resultCode, empty DN, empty diagnostic) }
        const auto rc = static_cast<std::uint8_t>(result_code_);
        const std::array<unsigned char, 14> response{
            0x30, 0x0c,
            0x02, 0x01, 0x01,
            0x61, 0x07,
            0x0a, 0x01, rc,
            0x04, 0x00,
            0x04, 0x00};

        asio::async_write(
            *socket_,
            asio::buffer(response),
            [this](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    error_ = ec;
                }
            });
    }

    tcp::acceptor acceptor_;
    std::optional<tcp::socket> socket_;
    std::array<unsigned char, 4096> request_buffer_{};
    int result_code_;
    boost::system::error_code error_;
};

void test_successful_bind()
{
    asio::io_context io;
    fake_ldap_server server(io, 0);
    server.start();

    boost_openldap::client client(
        io,
        "ldap://127.0.0.1:" + std::to_string(server.port()));

    bool called = false;
    std::error_code callback_error;
    boost_openldap::bind_result callback_result;

    client.async_bind(
        {"cn=test,dc=example,dc=com", "secret"},
        [&](std::error_code ec, boost_openldap::bind_result result) {
            called = true;
            callback_error = ec;
            callback_result = result;
        });

    io.run();

    assert(called);
    assert(!callback_error);
    assert(callback_result.ldap_result == 0);
}

void test_invalid_credentials()
{
    asio::io_context io;
    fake_ldap_server server(io, 49); // LDAP_INVALID_CREDENTIALS
    server.start();

    boost_openldap::client client(
        io,
        "ldap://127.0.0.1:" + std::to_string(server.port()));

    bool called = false;
    std::error_code callback_error;
    boost_openldap::bind_result callback_result;

    client.async_bind(
        {"cn=test,dc=example,dc=com", "wrong"},
        [&](std::error_code ec, boost_openldap::bind_result result) {
            called = true;
            callback_error = ec;
            callback_result = result;
        });

    io.run();

    assert(called);
    assert(callback_error.category() == boost_openldap::ldap_error_category());
    assert(callback_error.value() == 49);
    assert(callback_result.ldap_result == 49);
}

int main()
{
    test_successful_bind();
    test_invalid_credentials();
    std::cout << "async bind tests passed\n";
}
