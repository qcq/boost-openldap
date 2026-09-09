#pragma once

#include "boost_openldap/connection.hpp"
#include "boost_openldap/error.hpp"
#include "boost_openldap/types.hpp"

#include <boost/asio/post.hpp>

#include <ldap.h>

#include <memory>
#include <system_error>
#include <type_traits>
#include <utility>

namespace boost_openldap {

struct client::implementation {
    implementation(boost::asio::io_context& io, std::string uri)
        : connection_(io, uri.c_str())
    {
    }

    connection connection_;

    template <typename Handler>
    void async_bind(bind_request request, Handler&& handler)
    {
        using handler_type = std::decay_t<Handler>;
        auto op = std::make_shared<bind_operation<handler_type>>(
            connection_, std::forward<Handler>(handler), std::move(request));
        op->start();
    }

private:
    template <typename Handler>
    class bind_operation : public std::enable_shared_from_this<bind_operation<Handler>> {
    public:
        bind_operation(connection& connection, Handler&& handler, bind_request request)
            : connection_(connection),
              handler_(std::forward<Handler>(handler)),
              request_(std::move(request))
        {
        }

        void start()
        {
            auto self = this->shared_from_this();
            boost::asio::post(connection_.executor(), [self]() mutable {
                self->start_on_executor();
            });
        }

    private:
        void start_on_executor()
        {
            const auto ec = connection_.ensure_connected();
            if (ec == make_error_code(errc::connection_in_progress)) {
                wait_for_connect();
                return;
            }
            if (ec) {
                complete(ec, {});
                return;
            }
            submit_bind();
        }

        void wait_for_connect()
        {
            auto self = this->shared_from_this();
            connection_.descriptor().async_wait(
                boost::asio::posix::stream_descriptor::wait_write,
                [self](const boost::system::error_code& ec) mutable {
                    if (ec) {
                        self->complete(
                            std::error_code(ec.value(), std::system_category()), {});
                        return;
                    }

                    const auto connect_ec = self->connection_.finish_connect();
                    if (connect_ec == make_error_code(errc::connection_in_progress)) {
                        self->wait_for_connect();
                        return;
                    }
                    if (connect_ec) {
                        self->complete(connect_ec, {});
                        return;
                    }
                    self->submit_bind();
                });
        }

        void submit_bind()
        {
            berval credential{};
            credential.bv_val = const_cast<char*>(request_.password.data());
            credential.bv_len = request_.password.size();

            int msgid = -1;
            const int rc = ldap_sasl_bind(
                connection_.native_handle(),
                request_.dn.c_str(),
                LDAP_SASL_SIMPLE,
                &credential,
                nullptr,
                nullptr,
                &msgid);

            if (rc != LDAP_SUCCESS) {
                complete(make_ldap_error(rc), {});
                return;
            }

            msgid_ = msgid;
            wait_for_result();
        }

        void wait_for_result()
        {
            auto self = this->shared_from_this();
            connection_.descriptor().async_wait(
                boost::asio::posix::stream_descriptor::wait_read,
                [self](const boost::system::error_code& ec) mutable {
                    if (ec) {
                        self->complete(
                            std::error_code(ec.value(), std::system_category()), {});
                        return;
                    }
                    self->consume_result();
                });
        }

        void consume_result()
        {
            LDAPMessage* message = nullptr;
            timeval timeout{0, 0};
            const int rc = ldap_result(
                connection_.native_handle(), msgid_, LDAP_MSG_ONE, &timeout, &message);

            if (rc == 0) {
                wait_for_result();
                return;
            }

            if (rc == -1) {
                complete(ldap_error_from_handle(), {});
                return;
            }

            if (message == nullptr) {
                complete(make_error_code(errc::ldap_error), {});
                return;
            }

            const int ldap_rc = ldap_result2error(
                connection_.native_handle(), message, 0);
            ldap_msgfree(message);

            bind_result result;
            result.ldap_result = ldap_rc;

            if (ldap_rc != LDAP_SUCCESS) {
                complete(make_ldap_error(ldap_rc), std::move(result));
                return;
            }

            complete({}, std::move(result));
        }

        void complete(std::error_code ec, bind_result result)
        {
            if (completed_) {
                return;
            }
            completed_ = true;
            handler_(ec, std::move(result));
        }

        std::error_code ldap_error_from_handle() const
        {
            int rc = LDAP_OTHER;
            if (ldap_get_option(
                    connection_.native_handle(), LDAP_OPT_RESULT_CODE, &rc) != LDAP_OPT_SUCCESS) {
                rc = LDAP_OTHER;
            }
            return make_ldap_error(rc);
        }

        connection& connection_;
        Handler handler_;
        bind_request request_;
        int msgid_ = -1;
        bool completed_ = false;
    };
};

} // namespace boost_openldap
