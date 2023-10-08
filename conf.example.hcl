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
}
