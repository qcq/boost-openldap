#include <boost_openldap.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

class fake_ldap_server {
public:
    fake_ldap_server(asio::io_context& io, int result_code)
        : acceptor_(io, tcp::endpoint(tcp::v4(), 0)), result_code_(result_code) {
        response_[0]=0x30; response_[1]=0x0c; response_[2]=0x02; response_[3]=0x01;
        response_[4]=0x01; response_[5]=0x61; response_[6]=0x07; response_[7]=0x0a;
        response_[8]=0x01; response_[9]=static_cast<std::uint8_t>(result_code_);
        response_[10]=0x04; response_[11]=0x00; response_[12]=0x04; response_[13]=0x00;
    }
    unsigned short port() const { return acceptor_.local_endpoint().port(); }
    void start() {
        acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
            if (ec) { error_=ec; return; }
            socket_=std::move(socket);
            socket_->async_read_some(asio::buffer(request_buffer_), [this](const boost::system::error_code& read_ec, std::size_t) {
                if (read_ec) error_=read_ec; else send_bind_response();
            });
        });
    }
    boost::system::error_code error() const { return error_; }
private:
    void send_bind_response() {
        asio::async_write(*socket_, asio::buffer(response_), [this](const boost::system::error_code& ec, std::size_t) { if (ec) error_=ec; });
    }
    tcp::acceptor acceptor_;
    std::optional<tcp::socket> socket_;
    std::array<unsigned char,4096> request_buffer_{};
    std::array<unsigned char,14> response_{};
    int result_code_;
    boost::system::error_code error_;
};

class fake_search_server {
public:
    explicit fake_search_server(asio::io_context& io) : acceptor_(io, tcp::endpoint(tcp::v4(), 0)) {
        entry_ = {0x30,0x32,0x02,0x01,0x01,0x64,0x2d,0x04,0x1a,
                  'c','n','=','a','l','i','c','e',',','d','c','=','e','x','a','m','p','l','e',',','d','c','=','c','o','m',
                  0x30,0x0f,0x30,0x0d,0x04,0x02,'c','n',0x31,0x07,0x04,0x05,'a','l','i','c','e'};
        done_ = {0x30,0x0c,0x02,0x01,0x01,0x65,0x07,0x0a,0x01,0x00,0x04,0x00,0x04,0x00};
    }
    unsigned short port() const { return acceptor_.local_endpoint().port(); }
    void start() {
        acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
            if (ec) { error_=ec; return; }
            socket_=std::move(socket);
            socket_->async_read_some(asio::buffer(request_buffer_), [this](const boost::system::error_code& read_ec, std::size_t) {
                if (read_ec) { error_=read_ec; return; } send_entry();
            });
        });
    }
    boost::system::error_code error() const { return error_; }
private:
    void send_entry() {
        asio::async_write(*socket_, asio::buffer(entry_), [this](const boost::system::error_code& ec, std::size_t) {
            if (ec) { error_=ec; return; } send_done();
        });
    }
    void send_done() {
        asio::async_write(*socket_, asio::buffer(done_), [this](const boost::system::error_code& ec, std::size_t) { if (ec) error_=ec; });
    }
    tcp::acceptor acceptor_;
    std::optional<tcp::socket> socket_;
    std::array<unsigned char,4096> request_buffer_{};
    std::vector<unsigned char> entry_;
    std::array<unsigned char,14> done_{};
    boost::system::error_code error_;
};

void test_successful_bind() {
    asio::io_context io; fake_ldap_server server(io,0); server.start();
    boost_openldap::client client(io,"ldap://127.0.0.1:"+std::to_string(server.port()));
    bool called=false, inside_initiation=true; std::error_code callback_error; boost_openldap::bind_result callback_result;
    client.async_bind({"cn=test,dc=example,dc=com","secret"},[&](std::error_code ec, boost_openldap::bind_result result){
        assert(!inside_initiation); called=true; callback_error=ec; callback_result=result;
    });
    inside_initiation=false; io.run();
    assert(called && !callback_error && callback_result.ldap_result==0 && !server.error());
}

void test_invalid_credentials() {
    asio::io_context io; fake_ldap_server server(io,49); server.start();
    boost_openldap::client client(io,"ldap://127.0.0.1:"+std::to_string(server.port()));
    bool called=false; std::error_code callback_error; boost_openldap::bind_result callback_result;
    client.async_bind({"cn=test,dc=example,dc=com","wrong"},[&](std::error_code ec, boost_openldap::bind_result result){ called=true; callback_error=ec; callback_result=result; });
    io.run();
    assert(called && callback_error.category()==boost_openldap::ldap_error_category() && callback_error.value()==49 && callback_result.ldap_result==49 && !server.error());
}

void test_use_future() {
    asio::io_context io; fake_ldap_server server(io,0); server.start();
    boost_openldap::client client(io,"ldap://127.0.0.1:"+std::to_string(server.port()));
    auto future=client.async_bind({"cn=test,dc=example,dc=com","secret"},asio::use_future); io.run();
    const auto result=future.get(); assert(!std::get<0>(result) && std::get<1>(result).ldap_result==0 && !server.error());
}

asio::awaitable<void> bind_coroutine(boost_openldap::client& client,bool& completed) {
    const auto result=co_await client.async_bind({"cn=test,dc=example,dc=com","secret"},asio::use_awaitable);
    completed=std::get<1>(result).ldap_result==0 && !std::get<0>(result); co_return;
}

void test_use_awaitable() {
    asio::io_context io; fake_ldap_server server(io,0); server.start();
    boost_openldap::client client(io,"ldap://127.0.0.1:"+std::to_string(server.port()));
    bool completed=false; asio::co_spawn(io,bind_coroutine(client,completed),asio::detached); io.run();
    assert(completed && !server.error());
}

void test_search() {
    asio::io_context io; fake_search_server server(io); server.start();
    boost_openldap::client client(io,"ldap://127.0.0.1:"+std::to_string(server.port()));
    bool called=false; std::error_code callback_error; boost_openldap::search_result result;
    boost_openldap::search_request request;
    request.base_dn="dc=example,dc=com"; request.filter="(objectClass=person)"; request.attributes={"cn"};
    client.async_search(std::move(request),[&](std::error_code ec, boost_openldap::search_result value){ called=true; callback_error=ec; result=std::move(value); });
    io.run();
    assert(called && !callback_error && result.ldap_result==0 && !server.error());
    assert(result.entries.size()==1 && result.entries[0].dn=="cn=alice,dc=example,dc=com");
    assert(result.entries[0].attributes.size()==1 && result.entries[0].attributes[0].name=="cn");
    assert(result.entries[0].attributes[0].values.size()==1 && result.entries[0].attributes[0].values[0]=="alice");
}

int main() {
    test_successful_bind(); test_invalid_credentials(); test_use_future(); test_use_awaitable(); test_search();
    std::cout << "async LDAP tests passed\n";
}
