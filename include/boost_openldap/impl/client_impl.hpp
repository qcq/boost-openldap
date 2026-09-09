#pragma once

#include "boost_openldap/connection.hpp"
#include "boost_openldap/error.hpp"
#include "boost_openldap/types.hpp"

#include <boost/asio/post.hpp>

#include <ldap.h>

#include <memory>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

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

    template <typename Handler>
    void async_search(search_request request, Handler&& handler)
    {
        using handler_type = std::decay_t<Handler>;
        auto op = std::make_shared<search_operation<handler_type>>(
            connection_, std::forward<Handler>(handler), std::move(request));
        op->start();
    }

private:
    template <typename Handler>
    class bind_operation : public std::enable_shared_from_this<bind_operation<Handler>> {
    public:
        bind_operation(connection& connection, Handler&& handler, bind_request request)
            : connection_(connection), handler_(std::forward<Handler>(handler)), request_(std::move(request))
        {
        }

        void start()
        {
            auto self = this->shared_from_this();
            boost::asio::post(connection_.executor(), [self]() mutable { self->start_on_executor(); });
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
                        self->complete(std::error_code(ec.value(), std::system_category()), {});
                        return;
                    }
                    const auto connect_ec = self->connection_.finish_connect();
                    if (connect_ec == make_error_code(errc::connection_in_progress)) {
                        self->wait_for_connect();
                    } else if (connect_ec) {
                        self->complete(connect_ec, {});
                    } else {
                        self->submit_bind();
                    }
                });
        }

        void submit_bind()
        {
            berval credential{};
            credential.bv_val = const_cast<char*>(request_.password.data());
            credential.bv_len = request_.password.size();
            int msgid = -1;
            const int rc = ldap_sasl_bind(
                connection_.native_handle(), request_.dn.c_str(), LDAP_SASL_SIMPLE,
                &credential, nullptr, nullptr, &msgid);
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
                        self->complete(std::error_code(ec.value(), std::system_category()), {});
                    } else {
                        self->consume_result();
                    }
                });
        }

        void consume_result()
        {
            LDAPMessage* message = nullptr;
            timeval timeout{0, 0};
            const int rc = ldap_result(connection_.native_handle(), msgid_, LDAP_MSG_ONE, &timeout, &message);
            if (rc == 0) {
                wait_for_result();
                return;
            }
            if (rc == -1) {
                complete(ldap_error_from_handle(), {});
                return;
            }
            if (!message) {
                complete(make_error_code(errc::ldap_error), {});
                return;
            }

            int ldap_rc = LDAP_OTHER;
            const int parse_rc = ldap_parse_result(
                connection_.native_handle(), message, &ldap_rc,
                nullptr, nullptr, nullptr, nullptr, 1);
            if (parse_rc != LDAP_SUCCESS) {
                complete(make_ldap_error(parse_rc), {});
                return;
            }

            bind_result result{ldap_rc};
            if (ldap_rc != LDAP_SUCCESS) {
                complete(make_ldap_error(ldap_rc), std::move(result));
            } else {
                complete({}, std::move(result));
            }
        }

        void complete(std::error_code ec, bind_result result)
        {
            if (completed_) return;
            completed_ = true;
            handler_(ec, std::move(result));
        }

        std::error_code ldap_error_from_handle() const
        {
            int rc = LDAP_OTHER;
            if (ldap_get_option(connection_.native_handle(), LDAP_OPT_RESULT_CODE, &rc) != LDAP_OPT_SUCCESS) {
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

    template <typename Handler>
    class search_operation : public std::enable_shared_from_this<search_operation<Handler>> {
    public:
        search_operation(connection& connection, Handler&& handler, search_request request)
            : connection_(connection), handler_(std::forward<Handler>(handler)), request_(std::move(request))
        {
        }

        void start()
        {
            auto self = this->shared_from_this();
            boost::asio::post(connection_.executor(), [self]() mutable { self->start_on_executor(); });
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
            submit_search();
        }

        void wait_for_connect()
        {
            auto self = this->shared_from_this();
            connection_.descriptor().async_wait(
                boost::asio::posix::stream_descriptor::wait_write,
                [self](const boost::system::error_code& ec) mutable {
                    if (ec) {
                        self->complete(std::error_code(ec.value(), std::system_category()), {});
                        return;
                    }
                    const auto connect_ec = self->connection_.finish_connect();
                    if (connect_ec == make_error_code(errc::connection_in_progress)) {
                        self->wait_for_connect();
                    } else if (connect_ec) {
                        self->complete(connect_ec, {});
                    } else {
                        self->submit_search();
                    }
                });
        }

        void submit_search()
        {
            std::vector<char*> attrs;
            attrs.reserve(request_.attributes.size() + 1);
            for (auto& attribute : request_.attributes) {
                attrs.push_back(const_cast<char*>(attribute.c_str()));
            }
            if (!attrs.empty()) {
                attrs.push_back(nullptr);
            }

            int msgid = -1;
            const int rc = ldap_search_ext(
                connection_.native_handle(),
                request_.base_dn.c_str(),
                static_cast<int>(request_.scope),
                request_.filter.c_str(),
                attrs.empty() ? nullptr : attrs.data(),
                0,
                nullptr,
                nullptr,
                nullptr,
                0,
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
                        self->complete(std::error_code(ec.value(), std::system_category()), {});
                    } else {
                        self->consume_result();
                    }
                });
        }

        void consume_result()
        {
            LDAPMessage* message = nullptr;
            timeval timeout{0, 0};
            const int rc = ldap_result(connection_.native_handle(), msgid_, LDAP_MSG_ONE, &timeout, &message);
            if (rc == 0) {
                wait_for_result();
                return;
            }
            if (rc == -1) {
                complete(ldap_error_from_handle(), {});
                return;
            }
            if (!message) {
                complete(make_error_code(errc::ldap_error), {});
                return;
            }

            if (rc == LDAP_RES_SEARCH_ENTRY) {
                search_entry entry;
                const int parse_rc = parse_entry(message, entry);
                ldap_msgfree(message);
                if (parse_rc != LDAP_SUCCESS) {
                    complete(make_ldap_error(parse_rc), {});
                    return;
                }
                result_.entries.push_back(std::move(entry));
                wait_for_result();
                return;
            }

            int ldap_rc = LDAP_OTHER;
            const int parse_rc = ldap_parse_result(
                connection_.native_handle(), message, &ldap_rc,
                nullptr, nullptr, nullptr, nullptr, 1);
            if (parse_rc != LDAP_SUCCESS) {
                complete(make_ldap_error(parse_rc), {});
                return;
            }

            result_.ldap_result = ldap_rc;
            if (ldap_rc != LDAP_SUCCESS) {
                complete(make_ldap_error(ldap_rc), std::move(result_));
            } else {
                complete({}, std::move(result_));
            }
        }

        static int parse_entry(LDAPMessage* message, search_entry& entry)
        {
            char* dn = ldap_get_dn(nullptr, message);
            // ldap_get_dn requires a valid LDAP handle; the caller supplies it below.
            (void)dn;
            return LDAP_PARAM_ERROR;
        }

        int parse_entry_with_handle(LDAPMessage* message, search_entry& entry)
        {
            char* dn = ldap_get_dn(connection_.native_handle(), message);
            if (!dn) return LDAP_DECODING_ERROR;
            entry.dn = dn;
            ldap_memfree(dn);

            BerElement* ber = nullptr;
            char* attribute = ldap_first_attribute(connection_.native_handle(), message, &ber);
            while (attribute) {
                search_attribute output;
                output.name = attribute;
                struct berval** values = ldap_get_values_len(
                    connection_.native_handle(), message, attribute);
                if (values) {
                    for (berval** value = values; *value; ++value) {
                        output.values.emplace_back((*value)->bv_val, (*value)->bv_len);
                    }
                    ldap_value_free_len(values);
                }
                ldap_memfree(attribute);
                entry.attributes.push_back(std::move(output));
                attribute = ldap_next_attribute(connection_.native_handle(), message, ber);
            }
            if (ber) ber_free(ber, 0);
            return LDAP_SUCCESS;
        }

        void complete(std::error_code ec, search_result result)
        {
            if (completed_) return;
            completed_ = true;
            handler_(ec, std::move(result));
        }

        std::error_code ldap_error_from_handle() const
        {
            int rc = LDAP_OTHER;
            if (ldap_get_option(connection_.native_handle(), LDAP_OPT_RESULT_CODE, &rc) != LDAP_OPT_SUCCESS) {
                rc = LDAP_OTHER;
            }
            return make_ldap_error(rc);
        }

        connection& connection_;
        Handler handler_;
        search_request request_;
        search_result result_;
        int msgid_ = -1;
        bool completed_ = false;
    };
};

} // namespace boost_openldap
