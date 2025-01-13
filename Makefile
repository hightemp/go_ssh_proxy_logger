PROJECT_NAME = go_ssh_proxy_logger

.PHONY: build run clean

build:
	CGO_ENABLED=0 go build -o $(PROJECT_NAME) main.go

build-static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o $(PROJECT_NAME)_static main.go

run:
	./$(PROJECT_NAME)

clean:
	rm -f $(PROJECT_NAME)

clean_logs:
	rm -f logs/*.log