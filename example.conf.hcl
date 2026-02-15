server http {
    hosts = ["127.0.0.1"]
    # hosts = ["::1"]            # Listen on localhost (IPv6)
    # hosts = ["0.0.0.0", "::"]  # Listen on all interfaces (IPv4 + IPv6)
    port = 8000

    proxy a {
        from {
            host = "a.localhost:8000"
        }
        to {
            host = "127.0.0.1"
            port = 8001
        }
    }

    proxy b {
        from {
            path = "/b/"
        }
        to {
            host = "127.0.0.1"
            port = 8002
        }
        auth basic {
            realm = "basic auth b"
            credential_file = "example.htpasswd"
            # user: nsfisis
            # password: password
        }
    }

    proxy c {
        from {
            host = "c.localhost:8000"
            path = "/c/"
        }
        to {
            host = "127.0.0.1"
            port = 8003
        }
    }
}
