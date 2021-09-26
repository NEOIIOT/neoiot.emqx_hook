DATE       ?= $(shell date +%FT%T%z)
VERSION    ?= $(shell git describe --tags --always --dirty --abbrev=14)
GO_VERSION ?= $(shell go version | cut -d ' ' -f 3-)

# 0,1 是否显示日志命令
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

ENV = "local"

# 默认
.PHONY: all
all: help

.PHONY: example
example: ; $(info $(M) 展示自定义命令...) @ ## 自定义命令示例
	$Q echo "可以根据这个示例编写其他命令"

.PHONY: help
help: ; $(info $(M) 帮助:)	@ ## 显示帮助信息
	@grep -hE '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-17s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version: ; $(info $(M) 当前仓库 Git 版本:)	@ ## 显示当前仓库 Git 版本
	@echo $(VERSION)

.PHONY: docker
docker: ; $(info $(M) make docker:)	@ ## 显示帮助信息
	docker build -t itsneo1990/neoiot_emqx_hook:latest .
	docker push itsneo1990/neoiot_emqx_hook:latest

.PHONY: helm
helm: ; $(info $(M) make docker:)	@ ## 显示帮助信息
	helm upgrade -n neoiot emqx.exhook charts
