#include <boost_openldap.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
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
        response_[0] = 0x30;
        response_[1] = 0x0c;
        response_[2] = 0x02;
        response_[3] = 0x01;
        response_[4] = 0x01;
        response_[5] = 0x61;
        response_[6] = 0x07;
        response_[7] = 0x0a;
        response_[8] = 0x01;
        response_[9] = static_cast<std::uint8_t>(result_code_);
        response_[10] = 0x04;
        response_[11] = 0x00;
        response_[12] = 0x04;
        response_[13] = 0x00;
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
        asio::async_write(
            *socket_,
            asio::buffer(response_),
            [this](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    error_ = ec;
                }
            });
    }

    tcp::acceptor acceptor_;
    std::optional<tcp::socket> socket_;
    std::array<unsigned char, 4096> request_buffer_{};
    std::array<unsigned char, 14> response_{};
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
    assert(!server.error());
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
    assert(!server.error());
}

int main()
{
    test_successful_bind();
    test_invalid_credentials();
    std::cout << "async bind tests passed\n";
}
