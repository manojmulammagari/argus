.PHONY: install run-backend run-frontend run-all test build clean infra

install:
	cd backend && pip install -r requirements-dev.txt
	cd frontend && npm install

infra:
	docker compose up -d

run-backend:
	cd backend && uvicorn main_api:app --reload --host 0.0.0.0 --port 8000

run-frontend:
	cd frontend && npm run dev

run-all:
	@trap 'kill 0' EXIT INT TERM; \
	(cd backend && uvicorn main_api:app --reload --host 0.0.0.0 --port 8000) & \
	(cd frontend && npm run dev) & \
	wait

test:
	cd backend && pytest -q

build:
	cd frontend && npm run build

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf frontend/.next
