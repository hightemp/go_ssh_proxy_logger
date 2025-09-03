package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type SSHServer struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	KeyFile  string `yaml:"key_file"`
}

type Service struct {
	Name                  string `yaml:"name"`
	SSHServerName         string `yaml:"ssh_server_name"`
	SSHRemoteListenPort   string `yaml:"ssh_remote_listen_port"`
	DestUrl               string `yaml:"dest_url"`
	LogFile               string `yaml:"log_file"`
	RequestMode           string `yaml:"request_mode"`
	TLSInsecureSkipVerify bool   `yaml:"tls_insecure_skip_verify"`
	SSHServer             *SSHServer
	Config                *Config
	SSHConfig             *ssh.ClientConfig
}

type Config struct {
	Services   []Service   `yaml:"services"`
	SSHServers []SSHServer `yaml:"ssh_servers"`
}

type SSHConnManager struct {
	mu      sync.Mutex
	conns   map[string]*ssh.Client
	dialing map[string]*dialState
}

type dialState struct {
	ready chan struct{}
	err   error
}

func NewSSHConnManager() *SSHConnManager {
	return &SSHConnManager{
		conns:   make(map[string]*ssh.Client),
		dialing: make(map[string]*dialState),
	}
}

var sshMgr = NewSSHConnManager()

func (m *SSHConnManager) GetOrDial(name, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	m.mu.Lock()
	if c, ok := m.conns[name]; ok && c != nil {
		m.mu.Unlock()
		return c, nil
	}
	if st, ok := m.dialing[name]; ok {
		ch := st.ready
		m.mu.Unlock()
		<-ch
		m.mu.Lock()
		c := m.conns[name]
		err := st.err
		m.mu.Unlock()
		if c != nil {
			return c, nil
		}
		return nil, err
	}
	st := &dialState{ready: make(chan struct{})}
	m.dialing[name] = st
	m.mu.Unlock()

	c, err := ssh.Dial("tcp", addr, cfg)

	m.mu.Lock()
	if err == nil {
		m.conns[name] = c
	}
	st.err = err
	delete(m.dialing, name)
	close(st.ready)
	m.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return c, nil
}

func (m *SSHConnManager) Invalidate(name string, client *ssh.Client) {
	m.mu.Lock()
	if c, ok := m.conns[name]; ok && c == client {
		delete(m.conns, name)
	}
	m.mu.Unlock()
}

func loadConfig(filePath string) (*Config, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	err = yaml.Unmarshal(bytes, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) FindSSHServerByName(name string) *SSHServer {
	for i := range c.SSHServers {
		if c.SSHServers[i].Name == name {
			return &c.SSHServers[i]
		}
	}
	return nil
}

func (s *Service) readPublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatal(err)
	}
	return ssh.PublicKeys(key)
}

func (s *Service) PrepareSSH() {
	s.SSHServer = s.Config.FindSSHServerByName(s.SSHServerName)
	if s.SSHServer == nil {
		log.Fatalf("ssh server '%s' not found", s.SSHServerName)
	}

	if s.SSHServer.Password != "" {
		s.SSHConfig = &ssh.ClientConfig{
			User: s.SSHServer.User,
			Auth: []ssh.AuthMethod{
				ssh.PasswordCallback(func() (string, error) { return s.SSHServer.Password, nil }),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else if s.SSHServer.KeyFile != "" {
		s.SSHConfig = &ssh.ClientConfig{
			User: s.SSHServer.User,
			Auth: []ssh.AuthMethod{
				s.readPublicKeyFile(s.SSHServer.KeyFile),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		log.Fatalf("ssh server '%s' has no auth method", s.SSHServerName)
	}
}

func (s *Service) LogRequest(r *http.Request) error {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	var bodyBytes []byte
	var err error
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read request body for logging: %v", err)
			return err
		}
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	reqCopy := r.Clone(r.Context())
	reqCopy.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	dump, err := httputil.DumpRequest(reqCopy, true)
	if err != nil {
		log.Printf("[ERROR] Failed to dump request: %v", err)
		return err
	}

	f, err := os.OpenFile(s.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file: %v", err)
		return err
	}
	defer f.Close()

	logEntry := fmt.Sprintf("[%s] Request to %s\n%s\n\n", timestamp, r.URL.String(), string(dump))
	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("[ERROR] Failed to write to log file: %v", err)
		return err
	}

	return nil
}

func (s *Service) LogResponse(resp *http.Response, reqURL string) error {
	if resp == nil {
		log.Printf("[ERROR] Cannot log nil response")
		return fmt.Errorf("response is nil")
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	var bodyBytes []byte
	var err error
	if resp.Body != nil {
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read response body for logging: %v", err)
			return err
		}
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	respCopy := new(http.Response)
	*respCopy = *resp
	respCopy.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	dump, err := httputil.DumpResponse(respCopy, true)
	if err != nil {
		log.Printf("[ERROR] Failed to dump response: %v", err)
		return err
	}

	f, err := os.OpenFile(s.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file: %v", err)
		return err
	}
	defer f.Close()

	logEntry := fmt.Sprintf("[%s] Response from %s\n%s\n\n", timestamp, reqURL, string(dump))

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("[ERROR] Failed to write to log file: %v", err)
		return err
	}

	return nil
}

func (s *Service) ListenPortOnSSH() {
	addr := fmt.Sprintf("%s:%s", s.SSHServer.Host, s.SSHServer.Port)
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		log.Printf("Trying to listen on SSH server '%s'", s.SSHServerName)

		sshConn, err := sshMgr.GetOrDial(s.SSHServerName, addr, s.SSHConfig)
		if err != nil {
			log.Printf("[WARN] Fail to connect to SSH '%s': %v (retry in %s)", s.SSHServerName, err, backoff)
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}

		listener, err := sshConn.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", s.SSHRemoteListenPort))
		if err != nil {
			log.Printf("[WARN] Fail to listen port on '0.0.0.0:%s': %v (retry in %s)", s.SSHRemoteListenPort, err, backoff)
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}

		backoff = 1 * time.Second

		var client *http.Client

		requestMode := s.RequestMode
		if requestMode == "" {
			requestMode = "ssh"
		}

		if requestMode == "ssh" {

			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: s.TLSInsecureSkipVerify,
				},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return sshConn.DialContext(ctx, network, addr)
				},
			}
			client = &http.Client{
				Transport: transport,
			}
			log.Printf("Service '%s' configured to send requests through SSH tunnel", s.Name)
		} else {

			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: s.TLSInsecureSkipVerify,
				},
			}
			client = &http.Client{
				Transport: transport,
			}
			log.Printf("Service '%s' configured to send requests directly", s.Name)
		}

		mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Receive request from %s\n", r.RemoteAddr)

			var newRequestURL string
			if s.DestUrl != "" {
				destUrl, err := url.Parse(s.DestUrl)
				if err != nil {
					log.Printf("[ERROR] Bad dest_url for service '%s': %v", s.Name, err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				destUrl.Path = r.URL.Path
				destUrl.RawQuery = r.URL.RawQuery
				destUrl.Fragment = r.URL.Fragment

				newRequestURL = destUrl.String()
			} else {
				newRequestURL = r.URL.String()
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				log.Printf("[ERROR] Failed to read request body: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			newReq, err := http.NewRequest(r.Method, newRequestURL, bytes.NewBuffer(bodyBytes))
			if err != nil {
				log.Printf("[ERROR] Failed to create request: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if r.ContentLength > 0 {
				newReq.ContentLength = r.ContentLength
			}

			for key, values := range r.Header {
				for _, value := range values {
					newReq.Header.Add(key, value)
				}
			}

			if err := s.LogRequest(newReq); err != nil {
				log.Printf("[ERROR] Failed to log request: %v", err)
			}

			resp, err := client.Do(newReq)
			if err != nil {
				log.Printf("[ERROR] Failed to send request: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			if errResp := s.LogResponse(resp, newReq.URL.String()); errResp != nil {
				log.Printf("[ERROR] Failed to log response: %v", errResp)
			}

			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			w.WriteHeader(resp.StatusCode)

			if _, err := io.Copy(w, resp.Body); err != nil {
				log.Printf("[ERROR] Failed to copy response body: %v", err)
			}
		})

		log.Printf("Server listen: http://%s:%s\n", s.SSHServer.Host, s.SSHRemoteListenPort)
		if err := http.Serve(listener, mux); err != nil {
			log.Printf("[WARN] HTTP serve on %s:%s stopped: %v", s.SSHServer.Host, s.SSHRemoteListenPort, err)
		}

		sshMgr.Invalidate(s.SSHServerName, sshConn)
	}
}

func (s *Service) ListenLocalPort() {
	log.Printf("Starting local listener on port %s", s.SSHRemoteListenPort)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", s.SSHRemoteListenPort))
	if err != nil {
		log.Fatalf("Failed to start local listener: %v", err)
	}
	defer listener.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.TLSInsecureSkipVerify,
		},
	}
	client := &http.Client{
		Transport: transport,
	}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request from %s\n", r.RemoteAddr)

		if r.Method == http.MethodConnect {
			host := r.URL.Host
			if host == "" {
				host = r.Host
			}

			targetConn, err := net.Dial("tcp", host)
			if err != nil {
				log.Printf("[ERROR] Failed to connect to target: %v", err)
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer targetConn.Close()

			w.WriteHeader(http.StatusOK)

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				log.Printf("[ERROR] Hijacking not supported")
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}

			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				log.Printf("[ERROR] Failed to hijack connection: %v", err)
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer clientConn.Close()

			err = s.LogRequest(r)
			if err != nil {
				log.Printf("[ERROR] Failed to log CONNECT request: %v", err)
			}

			go func() {
				_, err := io.Copy(targetConn, clientConn)
				if err != nil {
					log.Printf("[ERROR] Error copying to target: %v", err)
				}
			}()

			_, err = io.Copy(clientConn, targetConn)
			if err != nil {
				log.Printf("[ERROR] Error copying to client: %v", err)
			}

			return
		}

		destUrl, err := url.Parse(s.DestUrl)
		if err != nil {
			log.Fatal(err)
		}

		destUrl.Path = r.URL.Path
		destUrl.RawQuery = r.URL.RawQuery
		destUrl.Fragment = r.URL.Fragment

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read request body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		newReq, err := http.NewRequest(r.Method, destUrl.String(), bytes.NewBuffer(bodyBytes))
		if err != nil {
			log.Printf("[ERROR] Failed to create request: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if r.ContentLength > 0 {
			newReq.ContentLength = r.ContentLength
		}

		for key, values := range r.Header {
			for _, value := range values {
				newReq.Header.Add(key, value)
			}
		}

		err = s.LogRequest(newReq)
		if err != nil {
			log.Fatal(err)
		}

		resp, err := client.Do(newReq)
		if err != nil {
			log.Printf("[ERROR] Failed to send request: %s - %v", destUrl.String(), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		errResp := s.LogResponse(resp, newReq.URL.String())
		if errResp != nil {
			log.Printf("[ERROR] Failed to log response: %v", errResp)
		}

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(resp.StatusCode)

		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to copy response body: %v", err)
		}
	})

	log.Printf("Local server listening on http://localhost:%s\n", s.SSHRemoteListenPort)
	err = http.Serve(listener, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Service) Start(cfg *Config) {
	s.Config = cfg

	if s.SSHServerName == "localhost" {
		s.ListenLocalPort()
	} else {
		s.PrepareSSH()
		s.ListenPortOnSSH()
	}
}

func main() {
	cfgfile := flag.String("c", "config.yaml", "config file path")
	flag.Parse()

	cfg, err := loadConfig(*cfgfile)
	if err != nil {
		log.Fatal(err)
	}

	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, os.Interrupt, syscall.SIGTERM)

	for _, service := range cfg.Services {
		go service.Start(cfg)
	}

	<-signChan
}
