.PHONY: build run docker-build docker-run docker-stop docker-remove

NAME = ghcr.io/ba0f3/mcp-server-wazuh

build:
	go build -o mcp-server-wazuh ./cmd/mcp-server-wazuh

run:
	go run ./cmd/mcp-server-wazuh

docker-build:
	docker build -t $(NAME) .

docker-run:
	docker run -it $(NAME)

docker-stop:
	docker stop $(NAME)

docker-remove:
	docker rm $(NAME)