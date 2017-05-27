///////////////////////////////////////////////////////////////////////////////
/// \author (c) Anthony Fieroni (bvbfan@abv.bg)
///             2017, Plovdiv, Bulgaria
///
/// \license The MIT License (MIT)
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.
///////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <string>
#include <unistd.h>
#include <exception>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#ifndef __SSLXX__
#define __SSLXX__

namespace sslxx {

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define openssl_client_method ::TLS_client_method()
#define openssl_server_method ::TLS_server_method()
#else
#define openssl_client_method ::SSLv23_client_method()
#define openssl_server_method ::SSLv23_server_method()
#endif

static
void init_openssl() {
    struct library_init {
        library_init() {
            ::SSL_library_init();
            ::OpenSSL_add_all_algorithms();
        }

        ~library_init() {
            ::EVP_cleanup();
        }
    };
    static library_init one_time_init;
}

class exception : public std::exception {
    const char *m_text;
public:
    exception(const char *text) : m_text(text) {}
    const char* what() const noexcept override { return m_text; }
};

class stream {
    SSL *m_ssl = nullptr;
public:
    stream(SSL *ssl) : m_ssl(ssl) {}

    stream(stream &&) = default;
    stream(const stream &) = delete;

    stream& operator=(stream &&) = default;
    stream& operator=(const stream &) = delete;

    ~stream() {
        if (!m_ssl) {
            return;
        }

        int fd = ::SSL_get_fd(m_ssl);
        ::SSL_free(m_ssl);

        if (fd != -1) {
            ::close(fd);
        }

        m_ssl = nullptr;
    }

    std::string receive() {
        ssize_t len = 0;
        std::string result;
        do {
            char buffer[256] = {};
            len = ::SSL_read(m_ssl, buffer, 255);
            if (len > 0) {
                result.append(buffer, len);
            }
        } while (len == 255);
        return result;
    }

    size_t send(const std::string &buffer) {
        auto len = ::SSL_write(m_ssl, buffer.data(), buffer.size());
        return len < 0 ? size_t(0) : size_t(len);
    }
};

class connector {
    SSL_CTX *m_ctx = nullptr;
    struct sockaddr_in m_addr = {};
public:
    connector(const char *addr, int port) {
        init_openssl();

        if (!(m_ctx = ::SSL_CTX_new(openssl_client_method))) {
            throw exception("Could not create ctx");
        }

        m_addr.sin_family = AF_INET;
        m_addr.sin_port = htons(port);
        ::inet_aton(addr, &m_addr.sin_addr);
    }

    ~connector() {
        if (m_ctx) {
            ::SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

    connector(connector &&) = default;
    connector(const connector &) = delete;

    connector& operator=(connector &&) = default;
    connector& operator=(const connector &) = delete;

    std::unique_ptr<stream> connect() {
        int fd = ::socket(PF_INET, SOCK_STREAM, 0);
        if (fd <= 0) {
            return { nullptr };
        }

        if (::connect(fd, (struct sockaddr *)&m_addr, sizeof(m_addr))) {
            ::close(fd);
            return { nullptr };
        }

        SSL *ssl = ::SSL_new(m_ctx);
        ::SSL_set_fd(ssl, fd);

        if (::SSL_connect(ssl) != 1) {
            ::SSL_free(ssl);
            ::close(fd);
        }

        return std::unique_ptr<stream>{ new stream(ssl) };
    }
};

class listener {
    int m_fd = 0;
    SSL_CTX *m_ctx = nullptr;

    void cleanup() {
        if (m_fd) {
            ::close(m_fd);
            m_fd = 0;
        }

        if (m_ctx) {
            ::SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
    }

public:
    listener(int port, const char *cert_file) {
        init_openssl();

        // NOTE: destructor will not be called on non-fully constructed object
        // thus cleanup should be called explicitly
        if (!(m_ctx = ::SSL_CTX_new(openssl_server_method))) {
            cleanup();
            throw exception("Could not create ctx");
        }

        ::SSL_CTX_set_ecdh_auto(m_ctx, 1);

        if (::SSL_CTX_use_certificate_file(m_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
            cleanup();
            throw exception("Could not use certificate file");
        }

        if (::SSL_CTX_use_PrivateKey_file(m_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
            cleanup();
            throw exception("Could not use private key");
        }

        m_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (m_fd <= 0) {
            cleanup();
            throw exception("Could not create socket");
        }

        struct sockaddr_in server = {};
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr.s_addr = INADDR_ANY;

        if (::bind(m_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
            cleanup();
            throw exception("Could not bind socket");
        }

        if (::listen(m_fd, 16) != 0) {
            cleanup();
            throw exception("Could not listen socket");
        }
    }

    listener(listener &&) = default;
    listener(const listener &) = delete;

    listener& operator=(listener &&) = default;
    listener& operator=(const listener &) = delete;

    ~listener() { cleanup(); }

    std::unique_ptr<stream> accept() {
        struct sockaddr_in client;
        int sock_len = sizeof(client);
        int fd = ::accept(m_fd, (struct sockaddr *)&client, (socklen_t*)&sock_len);
        if (fd <= 0) {
            return { nullptr };
        }

        SSL *ssl = ::SSL_new(m_ctx);
        ::SSL_set_fd(ssl, fd);

        if (::SSL_accept(ssl) <= 0) {
            ::SSL_free(ssl);
            ::close(fd);
            return { nullptr };
        }

        return std::unique_ptr<stream>{ new stream(ssl) };
    }
};

}

#endif // __SSLXX__
