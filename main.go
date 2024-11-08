package go_ssh_proxy_logger

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type SSHServer struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
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

	s.SSHConfig = &ssh.ClientConfig{
		User: sshserv.User,
		Auth: []ssh.AuthMethod{
			s.readPublicKeyFile(sshserv.KeyFile),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	logEntry := fmt.Sprintf("[%s] \n%s\n", timestamp, string(dump))
	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("[ERROR] Failed to write to log file: %v", err)
		return err
	}

	return nil
}

func (s *Service) ListenPortOnSSH() {
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.SSHServer.Host, s.SSHServer.Port), s.SSHConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	listener, err := conn.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", s.SSHRemoteListenPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Recieve request from %s\n", r.RemoteAddr)
		s.LogRequest(r)

		destUrl, err := url.Parse(s.DestUrl)
		if err != nil {
			log.Fatal(err)
		}

		destUrl.Path = r.URL.Path
		destUrl.RawQuery = r.URL.RawQuery
		destUrl.Fragment = r.URL.Fragment
		r.URL = destUrl

		client := &http.Client{}

		resp, err := client.Do(r)
		if err != nil {
			log.Printf("[ERROR] Failed to send request: %s - %v", destUrl.String(), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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

	log.Printf("Server listen: http://%s:%d\n", s.SSHServer.Host, s.SSHRemoteListenPort)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Service) Start(cfg *Config) {
	s.Config = cfg
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
