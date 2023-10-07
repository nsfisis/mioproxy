package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func startServer(
	s *Server,
	listener net.Listener,
	wg *sync.WaitGroup,
	sigCtx context.Context,
) {
	defer wg.Done()

	go func() {
		err := s.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server (%s): %s", s.Label(), err)
		}
	}()

	fmt.Printf("Started server (%s)\n", s.Label())

	// Wait until we receive a signal to stop the server.
	<-sigCtx.Done()

	// Gracefully shutdown the server with timeout.
	timeoutCtx, cancelTimeoutCtx := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelTimeoutCtx()
	s.Shutdown(timeoutCtx)

	fmt.Printf("Shutdown server (%s)\n", s.Label())
}

func downgradeToUser(uname string) error {
	// Get gid and uid.
	u, err := user.Lookup(uname)
	if err != nil {
		return err
	}
	// On POSIX system, gid and uid are integers.
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	// Set gid and uid.
	err = syscall.Setgid(gid)
	if err != nil {
		return err
	}
	err = syscall.Setuid(uid)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// Check mode
	if len(os.Args) == 3 && os.Args[1] == "-check" {
		configFileName := os.Args[2]
		_, err := LoadConfig(configFileName)
		if err != nil {
			log.Fatalf("%s", err)
		}
		return
	}

	// Load config.
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <config file>", os.Args[0])
	}
	configFileName := os.Args[1]
	config, err := LoadConfig(configFileName)
	if err != nil {
		log.Fatalf("Failed to load configuration: %s", err)
	}
	configFileDir := filepath.Dir(configFileName)

	// Set up listeners.
	var listeners []net.Listener
	for _, s := range config.Servers {
		l, err := NewListener(&s)
		if err != nil {
			log.Fatalf("Failed to create listener (%s:%d): %s", s.Host, s.Port, err)
		}
		listeners = append(listeners, l)
	}

	// Set up servers.
	var servers []*Server
	for _, s := range config.Servers {
		// Convert relative paths to absolute paths, based on config file location.
		if s.ACMEChallenge != nil {
			s.ACMEChallenge.Root = filepath.Join(configFileDir, s.ACMEChallenge.Root)
		}
		if s.TLSCertFile != "" {
			s.TLSCertFile = filepath.Join(configFileDir, s.TLSCertFile)
		}
		if s.TLSKeyFile != "" {
			s.TLSKeyFile = filepath.Join(configFileDir, s.TLSKeyFile)
		}
		servers = append(servers, NewServer(&s))
	}

	// Downgrade to non-root user.
	if config.User != "" {
		err := downgradeToUser(config.User)
		if err != nil {
			log.Fatalf("Failed to downgrade to user %s: %s", config.User, err)
		}
	}

	// Catch signals to stop servers.
	sigCtx, cancelSigCtx := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM, os.Interrupt, os.Kill,
	)
	defer cancelSigCtx()

	// Start servers.
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go startServer(s, listeners[i], &wg, sigCtx)
	}
	wg.Wait()
}
