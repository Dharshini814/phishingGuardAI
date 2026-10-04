# PhishGuard AI - Development Makefile

.PHONY: help setup install train start-backend start-frontend start docker-build docker-up docker-down clean test lint

# Default target
help:
	@echo "PhishGuard AI - Development Commands"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make setup          - Setup backend and frontend"
	@echo "  make install        - Install dependencies only"
	@echo "  make train          - Generate dataset and train ML models"
	@echo ""
	@echo "Development:"
	@echo "  make start          - Start both backend and frontend"
	@echo "  make start-backend  - Start backend server only"
	@echo "  make start-frontend - Start frontend server only"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   - Build Docker images"
	@echo "  make docker-up      - Start with Docker Compose"
	@echo "  make docker-down    - Stop Docker containers"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make test           - Run tests (when available)"
	@echo "  make lint           - Run code linting"

# Setup everything
setup: install train
	@echo "✅ Setup complete! Run 'make start' to launch the application."

# Install dependencies
install:
	@echo "📦 Installing backend dependencies..."
	cd backend && python -m venv venv && \
	(source venv/bin/activate || venv/Scripts/activate) && \
	pip install -r requirements.txt
	@echo "📦 Installing frontend dependencies..."
	cd frontend && npm install

# Train ML models
train:
	@echo "🤖 Generating dataset and training ML models..."
	cd backend && \
	(source venv/bin/activate || venv/Scripts/activate) && \
	python setup.py

# Start both servers
start:
	@echo "🚀 Starting PhishGuard AI..."
	@echo "Backend will be available at: http://localhost:8000"
	@echo "Frontend will be available at: http://localhost:5173"
	@echo "Press Ctrl+C to stop both servers"
	make -j2 start-backend start-frontend

# Start backend only
start-backend:
	@echo "🔧 Starting backend server..."
	cd backend && \
	(source venv/bin/activate || venv/Scripts/activate) && \
	uvicorn app:app --reload --port 8000

# Start frontend only
start-frontend:
	@echo "⚡ Starting frontend server..."
	cd frontend && npm run dev

# Docker commands
docker-build:
	@echo "🐳 Building Docker images..."
	docker-compose build

docker-up:
	@echo "🐳 Starting with Docker Compose..."
	docker-compose up -d
	@echo "✅ Services started:"
	@echo "  Backend:  http://localhost:8000"
	@echo "  Frontend: http://localhost:3000"

docker-down:
	@echo "🐳 Stopping Docker containers..."
	docker-compose down

# Maintenance
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf backend/venv
	rm -rf frontend/node_modules
	rm -rf frontend/dist
	rm -f backend/model/phishing_model.pkl
	rm -f backend/model/model_metrics.json
	rm -f backend/data/phishing_dataset.csv
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete

test:
	@echo "🧪 Running tests..."
	@echo "Note: Tests not implemented yet. Add your test commands here."

lint:
	@echo "🔍 Running code linting..."
	@echo "Backend (flake8):"
	cd backend && (source venv/bin/activate || venv/Scripts/activate) && \
	pip install flake8 && flake8 --max-line-length=100 --exclude=venv .
	@echo "Frontend (ESLint):"
	cd frontend && npm run lint 2>/dev/null || echo "ESLint not configured"