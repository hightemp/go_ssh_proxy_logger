package main

import (
	"bytes"
	"context"
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
	Name                string `yaml:"name"`
	SSHServerName       string `yaml:"ssh_server_name"`
	SSHRemoteListenPort string `yaml:"ssh_remote_listen_port"`
	DestUrl             string `yaml:"dest_url"`
	LogFile             string `yaml:"log_file"`
	RequestMode         string `yaml:"request_mode"` // "ssh" или "direct", по умолчанию "ssh"
	SSHServer           *SSHServer
	Config              *Config
	SSHConfig           *ssh.ClientConfig
}

type Config struct {
	Services   []Service   `yaml:"services"`
	SSHServers []SSHServer `yaml:"ssh_servers"`
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
	for _, srv := range c.SSHServers {
		if srv.Name == name {
			return &srv
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

	dump, err := httputil.DumpRequest(r, true)
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

	dump, err := httputil.DumpResponse(resp, true)
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
	log.Printf("Trying to listen on SSH server '%s'", s.SSHServerName)
	sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", s.SSHServer.Host, s.SSHServer.Port), s.SSHConfig)
	if err != nil {
		log.Fatalf("Fail to connect to SSH: %v", err)
	}
	defer sshConn.Close()

	listener, err := sshConn.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", s.SSHRemoteListenPort))
	if err != nil {
		log.Fatalf("Fail to listen port on '0.0.0.0:%s': %v", s.SSHRemoteListenPort, err)
	}
	defer listener.Close()

	var client *http.Client

	// Определяем режим отправки запросов
	requestMode := s.RequestMode
	if requestMode == "" {
		requestMode = "ssh" // по умолчанию через SSH
	}

	if requestMode == "ssh" {
		// Отправка через SSH туннель
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return sshConn.DialContext(ctx, network, addr)
			},
		}
		client = &http.Client{
			Transport: transport,
		}
		log.Printf("Service '%s' configured to send requests through SSH tunnel", s.Name)
	} else {
		// Прямая отправка запросов
		client = &http.Client{}
		log.Printf("Service '%s' configured to send requests directly", s.Name)
	}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Receive request from %s\n", r.RemoteAddr)

		var newRequestURL string
		if s.DestUrl != "" {
			destUrl, err := url.Parse(s.DestUrl)
			if err != nil {
				log.Fatal(err)
			}

			destUrl.Path = r.URL.Path
			destUrl.RawQuery = r.URL.RawQuery
			destUrl.Fragment = r.URL.Fragment

			newRequestURL = destUrl.String()
		} else {
			newRequestURL = r.URL.String()
		}

		newReq, err := http.NewRequest(r.Method, newRequestURL, r.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to create request: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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
			log.Printf("[ERROR] Failed to send request: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		errResp := s.LogResponse(resp, newReq.URL.String())
		if errResp != nil {
			log.Printf("[ERROR] Failed to log response: %v", errResp)
		}
		defer resp.Body.Close()

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

	log.Printf("Server listen: http://%s:%s\n", s.SSHServer.Host, s.SSHRemoteListenPort)
	err = http.Serve(listener, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Service) ListenLocalPort() {
	log.Printf("Starting local listener on port %s", s.SSHRemoteListenPort)

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%s", s.SSHRemoteListenPort))
	if err != nil {
		log.Fatalf("Failed to start local listener: %v", err)
	}
	defer listener.Close()

	client := &http.Client{}

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request from %s\n", r.RemoteAddr)

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

		// Копируем заголовки из оригинального запроса
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

		// Копируем заголовки ответа
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
