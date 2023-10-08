server http {
    host = "127.0.0.1"
    port = 8000

    proxy a {
        from {
            host = "a.localhost"
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
    }

    proxy c {
        from {
            host = "c.localhost"
            path = "/c/"
        }
        to {
            host = "127.0.0.1"
            port = 8003
        }
    }
}
