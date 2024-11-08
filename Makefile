PROJECT_NAME = go_ssh_proxy_logger

.PHONY: build run clean

build:
	CGO_ENABLED=0 go build -o $(PROJECT_NAME) main.go
	chmod +x $(PROJECT_NAME)

run:
	./$(PROJECT_NAME)

clean:
	rm -f $(PROJECT_NAME)