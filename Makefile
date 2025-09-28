.PHONY: help install dev test clean docker-build docker-run docker-logs docker-stop init-db

help:
	@echo "Available commands:"
	@echo "  install     - Install dependencies"
	@echo "  dev         - Run development server"
	@echo "  test        - Run tests"
	@echo "  clean       - Clean up temporary files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run with Docker Compose"
	@echo "  docker-logs - View Docker logs"
	@echo "  docker-stop - Stop Docker services"
	@echo "  init-db     - Initialize database schema"

install:
	pip install -r requirements.txt

dev:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v --cov=api --cov-report=html

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache/
	rm -rf htmlcov/

docker-build:
	docker build -f docker/Dockerfile -t threat-intel-graph:latest .

docker-run:
	docker-compose -f docker/docker-compose.yml up -d

docker-logs:
	docker-compose -f docker/docker-compose.yml logs -f

docker-stop:
	docker-compose -f docker/docker-compose.yml down

init-db:
	python scripts/init_database.py
