#pragma once

#include <boost/asio/async_result.hpp>

#include "boost_openldap/impl/client_impl.hpp"

namespace boost_openldap {

template <typename CompletionToken>
auto client::async_bind(bind_request request, CompletionToken&& token)
{
    using signature = void(std::error_code, bind_result);

    return boost::asio::async_initiate<CompletionToken, signature>(
        [this, request = std::move(request)](auto&& handler) mutable {
            impl_->async_bind(std::move(request), std::forward<decltype(handler)>(handler));
        },
        token);
}

template <typename CompletionToken>
auto client::async_search(search_request request, CompletionToken&& token)
{
    using signature = void(std::error_code, search_result);

    return boost::asio::async_initiate<CompletionToken, signature>(
        [this, request = std::move(request)](auto&& handler) mutable {
            impl_->async_search(std::move(request), std::forward<decltype(handler)>(handler));
        },
        token);
}

} // namespace boost_openldap
