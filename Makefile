ifneq (,$(wildcard .env))
    include .env
    export
endif


.PHONY: help
help:	## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: run
run: ## Run service
	poetry run app

.PHONY: tests
tests: ## Execute test
	poetry run coverage run -m pytest -v tests

.PHONY: coverage
coverage: ## Execute coverage
	poetry run coverage report -m
