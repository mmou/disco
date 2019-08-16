package libdisco

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ed25519"
)

var rootKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

var publicKeyVerifier func([]byte, []byte) bool

func init() {
	rootKey.publicKey, rootKey.privateKey, _ = ed25519.GenerateKey(rand.Reader)

	publicKeyVerifier = CreatePublicKeyVerifier(rootKey.publicKey)
}

func TestNoiseKK(t *testing.T) {

	// init
	clientConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: Noise_KK,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: Noise_KK,
	}

	// set up remote keys
	serverConfig.RemoteKey = clientConfig.KeyPair.PublicKey[:]
	clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey[:]

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err := listener.Accept()
		if err != nil {
			t.Fatal("a server cannot accept()")
		}
		var buf [100]byte
		n, err := serverSocket.Read(buf[:])
		if err != nil {
			t.Fatal("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Fatal("client message failed")
		}

		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Fatal("server can't write on socket")
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server", err)
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
	var buf [100]byte
	n, err := clientSocket.Read(buf[:])
	if err != nil {
		t.Fatal("client can't read server's answer")
	}
	if !bytes.Equal(buf[:n], []byte("ca va?")) {
		t.Fatal("server message failed")
	}
}

func TestNoiseNK(t *testing.T) {

	test_pattern := Noise_NK

	// init
	clientConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: test_pattern,
	}
	serverConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: test_pattern,
	}

	// setup remote key
	clientConfig.RemoteKey = serverConfig.KeyPair.PublicKey[:]

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err := listener.Accept()
		if err != nil {
			t.Fatal("a server cannot accept()")
		}
		var buf [100]byte
		n, err := serverSocket.Read(buf[:])
		if err != nil {
			t.Fatal("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Fatal("client message failed")
		}

		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Fatal("server can't write on socket")
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server", err)
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
	var buf [100]byte
	n, err := clientSocket.Read(buf[:])
	if err != nil {
		t.Fatal("client can't read server's answer")
	}
	if !bytes.Equal(buf[:n], []byte("ca va?")) {
		t.Fatal("server message failed")
	}
}

func TestNoiseXX(t *testing.T) {

	// init
	clientKeyPair := GenerateKeypair(nil)
	clientConfig := Config{
		KeyPair:              clientKeyPair,
		HandshakePattern:     Noise_XX,
		PublicKeyVerifier:    publicKeyVerifier,
		StaticPublicKeyProof: CreateStaticPublicKeyProof(rootKey.privateKey, clientKeyPair.PublicKey[:]),
	}
	serverKeyPair := GenerateKeypair(nil)
	serverConfig := Config{
		KeyPair:              serverKeyPair,
		HandshakePattern:     Noise_XX,
		PublicKeyVerifier:    publicKeyVerifier,
		StaticPublicKeyProof: CreateStaticPublicKeyProof(rootKey.privateKey, serverKeyPair.PublicKey[:]),
	}

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err := listener.Accept()
		if err != nil {
			t.Fatal("a server cannot accept()")
		}
		var buf [100]byte
		n, err := serverSocket.Read(buf[:])
		if err != nil {
			t.Fatal("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Fatal("client message failed")
		}

		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Fatal("server can't write on socket")
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server", err)
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
	var buf [100]byte
	n, err := clientSocket.Read(buf[:])
	if err != nil {
		t.Fatal("client can't read server's answer")
	}
	if !bytes.Equal(buf[:n], []byte("ca va?")) {
		t.Fatal("server message failed")
	}
}

func TestNoiseN(t *testing.T) {

	// init
	serverConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: Noise_N,
	}

	clientConfig := Config{
		KeyPair:          GenerateKeypair(nil),
		HandshakePattern: Noise_N,
		RemoteKey:        serverConfig.KeyPair.PublicKey[:],
	}

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err2 := listener.Accept()
		if err2 != nil {
			t.Fatal("a server cannot accept()")
		}
		var buf [100]byte
		n, err2 := serverSocket.Read(buf[:])
		if err2 != nil {
			t.Fatal("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Fatal("client message failed")
		}

		/* TODO: test that this fails
		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Fatal("server can't write on socket")
		}
		*/

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server")
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
}

func TestNoiseIKpsk2(t *testing.T) {

	// init
	pskTemp, _ := hex.DecodeString("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
	psk := make([]byte, 32)
	copy(pskTemp[:32], psk[:32])
	serverKeyPair := GenerateKeypair(nil)
	serverConfig := Config{
		KeyPair:           serverKeyPair,
		HandshakePattern:  Noise_IKpsk2,
		PublicKeyVerifier: publicKeyVerifier,
		PreSharedKey:      psk,
	}
	clientKeyPair := GenerateKeypair(nil)
	clientConfig := Config{
		KeyPair:              clientKeyPair,
		RemoteKey:            serverKeyPair.PublicKey[:],
		HandshakePattern:     Noise_IKpsk2,
		StaticPublicKeyProof: CreateStaticPublicKeyProof(rootKey.privateKey, clientKeyPair.PublicKey[:]),
		PreSharedKey:         psk,
	}

	// get a Noise.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err := listener.Accept()
		if err != nil {
			t.Fatal("a server cannot accept()")
		}
		var buf [100]byte
		n, err := serverSocket.Read(buf[:])
		if err != nil {
			t.Fatal("server can't read on socket")
		}
		if !bytes.Equal(buf[:n], []byte("hello")) {
			t.Fatal("client message failed")
		}

		if _, err = serverSocket.Write([]byte("ca va?")); err != nil {
			t.Fatal("server can't write on socket")
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server", err)
	}
	_, err = clientSocket.Write([]byte("hello"))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
	var buf [100]byte
	n, err := clientSocket.Read(buf[:])
	if err != nil {
		t.Fatal("client can't read server's answer")
	}
	if !bytes.Equal(buf[:n], []byte("ca va?")) {
		t.Fatal("server message failed")
	}
}
