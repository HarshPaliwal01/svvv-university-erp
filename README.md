# SVVV University ERP (FastAPI + SQLite/PostgreSQL)

## Run in VS Code
1. Install Python 3.11+ and open this folder in VS Code.
2. Terminal:
   ```
   cd backend
   python -m venv venv
   venv\Scripts\activate        # Windows  (Mac/Linux: source venv/bin/activate)
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```
3. Open http://localhost:8000 (the backend also serves the frontend). API docs: http://localhost:8000/docs
4. Demo logins: admin/admin123, FAC101..FAC104/faculty123, SVVV2201..SVVV2204/student123.

The first start creates `svvv.db` and demo data. Delete it to reset.

## PostgreSQL
Create a database, copy `.env.example` values into your environment (DATABASE_URL, SECRET_KEY) and start again.

## Structure
- backend/main.py: models, JWT auth, role checks, attendance (manual/QR/photo), assignments, timetable conflicts, helpdesk, notices, analytics
- frontend/index.html: portal UI calling the API (camera needs localhost or https)
- Photo attendance: plug a face-recognition model into `identify_faces()` in main.py (needs student consent). By default nobody is identified, so everyone stays Pending for faculty review.

## Not built yet
Fees, exams/results, LMS, PDF/Excel reports, notification centre, Alembic migrations, React/Tailwind frontend.
