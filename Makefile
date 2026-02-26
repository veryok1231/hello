.PHONY: build clean test run install

BINARY_NAME=probe
MAIN_PATH=./cmd/probe

build:
	go build -o $(BINARY_NAME) $(MAIN_PATH)

install:
	go install $(MAIN_PATH)

clean:
	go clean
	rm -f $(BINARY_NAME)

test:
	go test -v ./...

run:
	go run $(MAIN_PATH)

deps:
	go mod download
	go mod tidy

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

.PHONY: help
help:
	@echo "可用命令:"
	@echo "  make build    - 编译项目"
	@echo "  make install  - 安装到 GOPATH/bin"
	@echo "  make clean    - 清理编译产物"
	@echo "  make test     - 运行测试"
	@echo "  make run      - 直接运行"
	@echo "  make deps     - 下载依赖"
	@echo "  make lint     - 运行代码检查"
	@echo "  make fmt      - 格式化代码"
