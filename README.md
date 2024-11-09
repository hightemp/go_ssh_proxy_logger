# SSH Tunnel Proxy

A Go application that creates HTTP proxies through SSH tunnels, allowing you to forward HTTP traffic through local server to specified destinations and logs all packets.

## Features

- Multiple service support
- Both password and key-based SSH authentication
- Request and response logging
- Configuration via YAML file

## Configuration

Create a `config.yaml` file:

```yaml
ssh_servers:
  - name: server1
    host: example.com
    port: "22"
    user: username
    # password: password  # Either password or key_file must be specified
    key_file: /path/to/private/key

services:
  - name: service1
    ssh_server_name: server1
    ssh_remote_listen_port: "8080"
    dest_url: "http://destination-service:8080"
    log_file: "logs/service1.log"
```