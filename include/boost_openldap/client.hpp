#pragma once

#include "boost_openldap/connection.hpp"
#include "boost_openldap/types.hpp"

#include <boost/asio/async_result.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace boost_openldap {

class client {
public:
    client(boost::asio::io_context& io, std::string uri);
    ~client();

    client(const client&) = delete;
    client& operator=(const client&) = delete;

    template <typename CompletionToken>
    auto async_bind(bind_request request, CompletionToken&& token);

    template <typename CompletionToken>
    auto async_search(search_request request, CompletionToken&& token);

private:
    struct implementation;
    std::unique_ptr<implementation> impl_;
};

} // namespace boost_openldap

#include "boost_openldap/impl/client.ipp"
