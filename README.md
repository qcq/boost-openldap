# boost-openldap

Modern asynchronous LDAP client for C++ based on Boost.Asio and OpenLDAP.

## Goal

Provide an Asio-style API around the OpenLDAP C client library (`libldap`), while keeping coroutine support optional. The primary async interface is based on Boost.Asio completion tokens, so existing callback-based applications can use the library without becoming coroutine-based.

## Initial architecture

```text
Application
    |
    v
boost-openldap
    |
    +-- async operation / message-id tracking
    |
    +-- Boost.Asio event integration
    |
    v
OpenLDAP libldap
    |
    v
LDAP / TLS
```

An LDAP handle may have multiple outstanding operations. Each operation is associated with the message ID returned by libldap; readable events on the LDAP socket drive result collection and dispatch.

## Planned API

```cpp
client.async_bind(request, [](error_code ec, bind_result result) {
    if (ec) {
        // handle error
        return;
    }
    // bind succeeded
});
```

The same async operation will later support Asio completion tokens such as `asio::use_awaitable` and `asio::use_future`.

## Status

Early development. The first milestone is the asynchronous operation framework and simple Bind operation.

## Dependencies

- C++20
- Boost.Asio
- OpenLDAP client library (`libldap`)
- CMake 3.20+
