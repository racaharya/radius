package radius

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

type packetResponseWriter struct {
	// listener that received the packet
	conn net.PacketConn
	addr net.Addr
}

func (r *packetResponseWriter) Write(packet *Packet) error {
	encoded, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.WriteTo(encoded, r.addr); err != nil {
		return err
	}
	return nil
}

// PacketServer listens for RADIUS requests on a packet-based protocols (e.g.
// UDP).
type PacketServer struct {
	// The address on which the server listens. Defaults to :1812.
	Addr string

	// The network on which the server listens. Defaults to udp.
	Network string

	// The source from which the secret is obtained for parsing and validating
	// the request.
	SecretSource SecretSource

	// Handler which is called to process the request.
	Handler Handler

	// Skip incoming packet authenticity validation.
	// This should only be set to true for debugging purposes.
	InsecureSkipVerify bool

	// ErrorLog specifies an optional logger for errors
	// around packet accepting, processing, and validation.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	shutdownRequested int32

	mu          sync.Mutex
	ctx         context.Context
	ctxDone     context.CancelFunc
	listeners   map[net.PacketConn]uint
	lastActive  chan struct{} // closed when the last active item finishes
	activeCount int32
}

func (s *PacketServer) initLocked() {
	if s.ctx == nil {
		s.ctx, s.ctxDone = context.WithCancel(context.Background())
		s.listeners = make(map[net.PacketConn]uint)
		s.lastActive = make(chan struct{})
	}
}

func (s *PacketServer) activeAdd() {
	atomic.AddInt32(&s.activeCount, 1)
}

func (s *PacketServer) activeDone() {
	if atomic.AddInt32(&s.activeCount, -1) == -1 {
		close(s.lastActive)
	}
}

func (s *PacketServer) logf(format string, args ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

/*
// Serve accepts incoming connections on conn.

	func (s *PacketServer) Serve(conn net.PacketConn) error {
		if s.Handler == nil {
			return errors.New("radius: nil Handler")
		}
		if s.SecretSource == nil {
			return errors.New("radius: nil SecretSource")
		}

		s.mu.Lock()
		s.initLocked()
		if atomic.LoadInt32(&s.shutdownRequested) == 1 {
			s.mu.Unlock()
			return ErrServerShutdown
		}

		s.listeners[conn]++
		s.mu.Unlock()

		type requestKey struct {
			IP         string
			Identifier byte
		}

		var (
			requestsLock sync.Mutex
			requests     = map[requestKey]struct{}{}
		)

		s.activeAdd()
		defer func() {
			s.mu.Lock()
			s.listeners[conn]--
			if s.listeners[conn] == 0 {
				delete(s.listeners, conn)
			}
			s.mu.Unlock()
			s.activeDone()
		}()

		var buff [MaxPacketLength]byte
		for {
			n, remoteAddr, err := conn.ReadFrom(buff[:])
			if err != nil {
				if atomic.LoadInt32(&s.shutdownRequested) == 1 {
					return ErrServerShutdown
				}

				if ne, ok := err.(net.Error); ok && !ne.Temporary() {
					return err
				}
				s.logf("radius: could not read packet: %v", err)
				continue
			}

			s.activeAdd()
			go func(buff []byte, remoteAddr net.Addr) {
				defer s.activeDone()

				secret, err := s.SecretSource.RADIUSSecret(s.ctx, remoteAddr)
				if err != nil {
					s.logf("radius: error fetching from secret source: %v", err)
					return
				}
				if len(secret) == 0 {
					s.logf("radius: empty secret returned from secret source")
					return
				}

				if !s.InsecureSkipVerify && !IsAuthenticRequest(buff, secret) {
					s.logf("radius: packet validation failed; bad secret")
					return
				}

				packet, err := Parse(buff, nil, secret)
				if err != nil {
					s.logf("radius: unable to parse packet: %v", err)
					return
				}

				key := requestKey{
					IP:         remoteAddr.String(),
					Identifier: packet.Identifier,
				}

				requestsLock.Lock()
				if _, ok := requests[key]; ok {
					requestsLock.Unlock()
					return
				}
				requests[key] = struct{}{}
				requestsLock.Unlock()

				response := packetResponseWriter{
					conn: conn,
					addr: remoteAddr,
				}

				defer func() {
					requestsLock.Lock()
					delete(requests, key)
					requestsLock.Unlock()
				}()

				request := Request{
					LocalAddr:  conn.LocalAddr(),
					RemoteAddr: remoteAddr,
					Packet:     packet,
					ctx:        s.ctx,
					Conn:       conn,
				}

				s.Handler.ServeRADIUS(&response, &request)
			}(append([]byte(nil), buff[:n]...), remoteAddr)
		}
	}
*/
type requestKey struct {
	IP         string
	Identifier byte
}

// Serve starts processing incoming packets on the specified net.PacketConn.
// It requires that both the Handler and SecretSource fields are non-nil,
// otherwise it returns an error. The function initializes internal server state
// and increments the listener counter for the connection.
//
// It creates a pool of buffers to minimize allocations and spawns multiple
// goroutines for reading packets (one per CPU core) from the connection.
// Each reader retrieves a buffer from the pool and blocks on reading a UDP packet.
// On a successful read, the packet data, its length, and the remote address are sent
// to a processing channel.
//
// In parallel, a set of worker goroutines (one per CPU core) continuously
// receive packets from the channel and process them using the handlePacket method.
// After processing, the buffer is returned to the pool.
//
// The function maintains a tracking map for concurrent requests and handles
// possible read errors including connection resets and shutdown signals.
// The function blocks indefinitely to keep the server running,
// and proper cleanup (decrementing listener count and waiting for goroutines to finish)
// is performed upon shutdown.
func (s *PacketServer) Serve(conn net.PacketConn) error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	s.mu.Lock()
	s.initLocked()
	if atomic.LoadInt32(&s.shutdownRequested) == 1 {
		s.mu.Unlock()
		return ErrServerShutdown
	}
	s.listeners[conn]++
	s.mu.Unlock()

	// Buffer pool (stores *[]byte to avoid allocations)
	packetPool := sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MaxPacketLength)
			return &buf // Return pointer to slice
		},
	}

	// Request tracking
	var (
		requestsLock sync.Mutex
		requests     = make(map[requestKey]struct{})
	)

	workerCount := runtime.NumCPU() // Use all available CPU cores

	// Packet processing channel
	packetCh := make(chan struct {
		buf        *[]byte
		n          int
		remoteAddr net.Addr
	}, workerCount*4) // Buffered to avoid blocking

	var wg sync.WaitGroup

	//Step 1: Spawn multiple UDP Readers
	for readers := 0; readers < workerCount; readers++ {
		wg.Add(1)
		go func() error {
			defer wg.Done()
			for {
				bufPtr := packetPool.Get().(*[]byte) // Retrieve buffer from pool
				n, remoteAddr, err := conn.ReadFrom(*bufPtr)
				if err != nil {
					packetPool.Put(bufPtr) // Return buffer to pool if read fails
					if atomic.LoadInt32(&s.shutdownRequested) == 1 {
						s.logf("radius: shutting down requested")
						return err
					}
					if errors.Is(err, net.ErrClosed) {
						s.logf("radius: connection closed")
						return err
					}
					if opErr, ok := err.(*net.OpError); ok {
						if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
							if errors.Is(sysErr.Err, syscall.ECONNRESET) || errors.Is(sysErr.Err, syscall.EPIPE) {
								s.logf("radius: connection reset by peer")
								return err
							}
						}
					}

					s.logf("radius: could not read packet: %v", err)
					continue
				}

				packetCh <- struct {
					buf        *[]byte
					n          int
					remoteAddr net.Addr
				}{bufPtr, n, remoteAddr}
			}
		}()
	}

	//Step 2: Spawn multiple workers to process packets
	for handlers := 0; handlers < workerCount; handlers++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkt := range packetCh {
				s.handlePacket((*pkt.buf)[:pkt.n], pkt.remoteAddr, conn, &requests, &requestsLock)
				packetPool.Put(pkt.buf) // Return buffer to pool after processing
			}
		}()
	}

	s.activeAdd()
	defer func() {
		s.mu.Lock()
		s.listeners[conn]--
		if s.listeners[conn] == 0 {
			delete(s.listeners, conn)
		}
		s.mu.Unlock()
		s.activeDone()

		close(packetCh) // Close channel to stop workers
		wg.Wait()       // Wait for all workers to finish
	}()

	// Block forever to keep the server running
	select {}
}

// handlePacket processes an incoming RADIUS packet from a remote client.
// It performs the following steps:
//  1. Retrieves the RADIUS secret for the remote address using s.SecretSource.
//  2. Validates the packet by checking for an empty secret and ensuring the packet's authenticity,
//     unless s.InsecureSkipVerify is set.
//  3. Parses the raw packet bytes into a RADIUS packet struct.
//  4. Deduplicates the request using a combination of the remote address and the packet's identifier,
//     preventing duplicate processing.
//  5. Creates a response writer and constructs a Request object containing connection and context data.
//  6. Passes the Request along with the response writer to the registered Handler's ServeRADIUS method.
//
// The function ensures cleanup by removing the request key from the deduplication map after processing.
func (s *PacketServer) handlePacket(
	buf []byte, remoteAddr net.Addr, conn net.PacketConn,
	requests *map[requestKey]struct{}, requestsLock *sync.Mutex) {

	secret, err := s.SecretSource.RADIUSSecret(s.ctx, remoteAddr)
	if err != nil {
		s.logf("radius: error fetching from secret source: %v", err)
		return
	}
	if len(secret) == 0 {
		s.logf("radius: empty secret returned from secret source")
		return
	}

	if !s.InsecureSkipVerify && !IsAuthenticRequest(buf, secret) {
		s.logf("radius: packet validation failed; bad secret")
		return
	}

	packet, err := Parse(buf, nil, secret)
	if err != nil {
		s.logf("radius: unable to parse packet: %v", err)
		return
	}

	// Deduplicate requests
	key := requestKey{
		IP:         remoteAddr.String(),
		Identifier: packet.Identifier,
	}

	requestsLock.Lock()
	if _, exists := (*requests)[key]; exists {
		requestsLock.Unlock()
		return
	}
	(*requests)[key] = struct{}{}
	requestsLock.Unlock()

	// Handle request
	response := packetResponseWriter{
		conn: conn,
		addr: remoteAddr,
	}

	defer func() {
		requestsLock.Lock()
		delete(*requests, key)
		requestsLock.Unlock()
	}()

	request := Request{
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: remoteAddr,
		Packet:     packet,
		ctx:        s.ctx,
		Conn:       conn,
	}

	s.Handler.ServeRADIUS(&response, &request)
}

// Listen listens on the given address with performance optimizations.
func (s *PacketServer) Listen() (net.PacketConn, error) {
	if s.Handler == nil {
		return nil, errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return nil, errors.New("radius: nil SecretSource")
	}

	// Set defaults directly (avoiding unnecessary allocations)
	addrStr := s.Addr
	if addrStr == "" {
		addrStr = ":1812"
	}
	network := s.Network
	if network == "" {
		network = "udp"
	}

	// Use ListenConfig to enable SO_REUSEADDR and SO_REUSEPORT (Linux-only)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

				// Enable SO_REUSEPORT only on Linux (avoid issues on macOS/Windows)
				if runtime.GOOS == "linux" {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}
			})
		},
	}

	// Create the packet connection with optimized socket settings
	pc, err := lc.ListenPacket(context.Background(), network, addrStr)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *PacketServer) ListenAndServe() error {
	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}
	if s.SecretSource == nil {
		return errors.New("radius: nil SecretSource")
	}

	// Set defaults directly (avoiding unnecessary allocations)
	addrStr := s.Addr
	if addrStr == "" {
		addrStr = ":1812"
	}
	network := s.Network
	if network == "" {
		network = "udp"
	}

	pc, err := net.ListenPacket(network, addrStr)
	if err != nil {
		return err
	}
	defer pc.Close()
	return s.Serve(pc)
}

// Shutdown gracefully stops the server. It first closes all listeners and then
// waits for any running handlers to complete.
//
// Shutdown returns after nil all handlers have completed. ctx.Err() is
// returned if ctx is canceled.
//
// Any Serve methods return ErrShutdown after Shutdown is called.
func (s *PacketServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if atomic.CompareAndSwapInt32(&s.shutdownRequested, 0, 1) {
		for listener := range s.listeners {
			listener.Close()
		}

		s.ctxDone()
		s.activeDone()
	}
	s.mu.Unlock()

	select {
	case <-s.lastActive:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
