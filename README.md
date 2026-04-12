# ThreatLens Web — Full Stack

React + Node/Express + MongoDB + Python Flask ML

## Folder Structure
```
ThreatLens-Web/
  frontend/        React app (Vite)
  backend/         Node.js Express API
  ml/              Your existing app.py (Flask ML service)
```

## Quick Start (run 3 terminals)

### Terminal 1 — Flask ML Service
```bash
cd ml
python app.py
# Runs on http://localhost:5000
```

### Terminal 2 — Node Backend
```bash
cd backend
npm install
cp .env.example .env     # edit MONGO_URI if needed
npm run dev
# Runs on http://localhost:3001
```

### Terminal 3 — React Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

## Prerequisites
- Python with trained model (run trainModel.py first)
- Node.js 18+
- MongoDB (local: mongodb://localhost:27017  OR  use MongoDB Atlas free tier)

## MongoDB Setup (local)
Install from https://www.mongodb.com/try/download/community
Then just run `mongod` — the backend creates the database automatically.

## MongoDB Atlas (cloud, free)
1. Create free account at mongodb.com/atlas
2. Create a cluster, get connection string
3. Paste it in backend/.env as MONGO_URI
