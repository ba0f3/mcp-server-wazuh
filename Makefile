.PHONY: build run docker-build docker-run docker-stop docker-remove

NAME = ghcr.io/ba0f3/mcp-server-wazuh

build:
	go build -o $(NAME) main.go

run:
	go run main.go

docker-build:
	docker build -t $(NAME) .

docker-run:
	docker run -it $(NAME)

docker-stop:
	docker stop $(NAME)

docker-remove:
	docker rm $(NAME)