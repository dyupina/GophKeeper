include .env
export
# export POSTGRES_USER
# export POSTGRES_PASSWORD
# export POSTGRES_DB
# export DB_HOST
# export SERVER_ADDRESS

# сборка клиента под 3 платформы и сервера, запуск сервера
all: win linux mac server

win: server
	@GOOS=windows go build -o output/client_win -ldflags "-X main.buildVersion=v1.0.1 -X main.buildDate=$(shell date +%Y/%m/%d)" ./cmd/client/*.go

linux: server
	@GOOS=linux go build -o output/client_linux -ldflags "-X main.buildVersion=v1.0.1 -X main.buildDate=$(shell date +%Y/%m/%d)" ./cmd/client/*.go

mac: server
	@GOOS=darwin go build -o output/client_mac  -ldflags "-X main.buildVersion=v1.0.1 -X main.buildDate=$(shell date +%Y/%m/%d)" ./cmd/client/*.go

server:
	@GOOS=linux go build -o output/server ./cmd/server/main.go

# для локального запуска
run_client: lint linux
	@./output/client_linux

# для локального запуска
run_server: check-master-key lint server
	./output/server

	# @POSTGRES_USER=${POSTGRES_USER} \
	# POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
	# POSTGRES_DB=${POSTGRES_DB} \
	# DB_HOST=${DB_HOST} \
	# SERVER_ADDRESS=${SERVER_ADDRESS} \

lint:
	golangci-lint run
	
test:
	mkdir -p coverage
	go test -coverprofile=coverage/coverage.out ./...
	go tool cover -func=coverage/coverage.out

check-master-key:
	@if [ -z "$$MASTER_KEY" ]; then \
		echo "MASTER_KEY is not set. Generating a new one..."; \
		export MASTER_KEY=$$(openssl rand -base64 32); \
		echo "MASTER_KEY=$$MASTER_KEY" >> .env; \
		echo "Generated MASTER_KEY: $$MASTER_KEY and saved to .env"; \
	fi

# удаление таблиц в бд и бинарников
clear:
	@export GOOSE_DRIVER=postgres
	@export GOOSE_DBSTRING=postgresql://${POSTGRES_USER}:${POSTGRES_USER}@${DB_HOST}:5432/${POSTGRES_DB}?sslmode=disable
	@export GOOSE_MIGRATION_DIR=internal/storage/migrations
	@goose down-to 0
	@rm -rf output/


all_docker: down up	

up:
	mkdir -p output/
	sudo docker-compose up -d --build

down:
	sudo rm -rf output/
	sudo docker-compose down
