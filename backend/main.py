"""SVVV University ERP - FastAPI backend (SQLite by default, PostgreSQL via DATABASE_URL)."""
import os, time, secrets, hashlib, random, datetime as dt
from pathlib import Path
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Integer, Boolean, Float, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DB = os.getenv("DATABASE_URL", "sqlite:///./svvv.db")
SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
engine = create_engine(DB, connect_args={"check_same_thread": False} if DB.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine)
UPLOADS = Path("uploads"); UPLOADS.mkdir(exist_ok=True)
SUBJECTS = ["Data Structures", "Operating Systems", "DBMS", "Mathematics III", "Software Engg"]
today = lambda: dt.date.today().isoformat()

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    name: Mapped[str] = mapped_column(String(100)); role: Mapped[str] = mapped_column(String(10), index=True)
    pw: Mapped[str] = mapped_column(String(200)); dept: Mapped[str] = mapped_column(String(50), default="CSE")
    sem: Mapped[int] = mapped_column(Integer, default=5); section: Mapped[str] = mapped_column(String(5), default="A")
    email: Mapped[str] = mapped_column(String(120), default=""); active: Mapped[bool] = mapped_column(Boolean, default=True)
class Attendance(Base):
    __tablename__ = "attendance"
    id: Mapped[int] = mapped_column(primary_key=True)
    date: Mapped[str] = mapped_column(String(10), index=True); subject: Mapped[str] = mapped_column(String(60), index=True)
    student_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(10)); source: Mapped[str] = mapped_column(String(10))
    marked_by: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
class QRSession(Base):
    __tablename__ = "qr_sessions"
    id: Mapped[int] = mapped_column(primary_key=True); subject: Mapped[str] = mapped_column(String(60))
    faculty_id: Mapped[str] = mapped_column(ForeignKey("users.id")); token: Mapped[str] = mapped_column(String(12), index=True)
    expires: Mapped[float] = mapped_column(Float); active: Mapped[bool] = mapped_column(Boolean, default=True)
class Assignment(Base):
    __tablename__ = "assignments"
    id: Mapped[int] = mapped_column(primary_key=True); subject: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(200)); due: Mapped[str] = mapped_column(String(10))
    max_marks: Mapped[int] = mapped_column(Integer); created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
class Submission(Base):
    __tablename__ = "submissions"
    id: Mapped[int] = mapped_column(primary_key=True); assignment_id: Mapped[int] = mapped_column(ForeignKey("assignments.id"), index=True)
    student_id: Mapped[str] = mapped_column(ForeignKey("users.id")); filename: Mapped[str] = mapped_column(String(200))
    stored: Mapped[str] = mapped_column(String(200)); marks: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    feedback: Mapped[str] = mapped_column(String(500), default="")
class Notice(Base):
    __tablename__ = "notices"
    id: Mapped[int] = mapped_column(primary_key=True); text: Mapped[str] = mapped_column(String(500))
    urgent: Mapped[bool] = mapped_column(Boolean, default=False); date: Mapped[str] = mapped_column(String(10))
class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[int] = mapped_column(primary_key=True); student_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    category: Mapped[str] = mapped_column(String(60)); message: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(30), default="Open")
class Lecture(Base):
    __tablename__ = "lectures"
    id: Mapped[int] = mapped_column(primary_key=True); day: Mapped[str] = mapped_column(String(3)); slot: Mapped[str] = mapped_column(String(5))
    subject: Mapped[str] = mapped_column(String(60)); faculty_id: Mapped[str] = mapped_column(ForeignKey("users.id")); room: Mapped[str] = mapped_column(String(20))
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True); who: Mapped[str] = mapped_column(String(30)); action: Mapped[str] = mapped_column(String(300)); ts: Mapped[float] = mapped_column(Float)

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 120_000).hex()
def check_pw(p, h): return secrets.compare_digest(hash_pw(p, h.split("$")[0]), h)

def get_db():
    s = SessionLocal()
    try: yield s
    finally: s.close()
bearer = HTTPBearer(auto_error=False)
def current(cred: HTTPAuthorizationCredentials = Depends(bearer), s: Session = Depends(get_db)) -> User:
    try: uid = jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])["sub"]
    except Exception: raise HTTPException(401, "Please sign in again.")
    u = s.get(User, uid)
    if not u or not u.active: raise HTTPException(401, "Account not available.")
    return u
def need(*roles):
    def dep(u: User = Depends(current)):
        if u.role not in roles: raise HTTPException(403, "You do not have access to this.")
        return u
    return dep
def log(s, who, action): s.add(AuditLog(who=who, action=action, ts=time.time()))
pub = lambda u: {"id": u.id, "name": u.name, "role": u.role, "dept": u.dept, "sem": u.sem, "section": u.section, "email": u.email}

app = FastAPI(title="SVVV University ERP")

def seed():
    Base.metadata.create_all(engine)
    with SessionLocal() as s:
        if s.scalar(select(func.count()).select_from(User)): return
        add = lambda i, n, r, p, **k: s.add(User(id=i, name=n, role=r, pw=hash_pw(p), email=n.lower().replace(" ", ".") + "@svvv.edu.in", **k))
        add("admin", "Registrar Office", "admin", "admin123")
        for i, n in enumerate(["Vishwas Dixit", "Priyanka Vishvakarma", "Priya Kothari", "Shyam Sundar Meena"], 1): add(f"FAC10{i}", n, "faculty", "faculty123")
        studs = ["Harsh Paliwal", "Durgesh Jaiswal", "Deepak Gupta", "Bhumika Mane"]
        for i, n in enumerate(studs, 1): add(f"SVVV220{i}", n, "student", "student123")
        random.seed(1)
        for d in range(1, 26):
            day = dt.date.today() - dt.timedelta(days=d)
            if day.weekday() > 4: continue
            for i in range(len(studs)):
                for sub in SUBJECTS:
                    s.add(Attendance(date=day.isoformat(), subject=sub, student_id=f"SVVV220{i+1}", status="P" if random.random() < 0.95 - i * 0.07 else "A", source="manual", marked_by="seed"))
        for day, slot, sub, fac, room in [("Mon", "9:00", "DBMS", "FAC101", "B-204"), ("Mon", "10:00", "Data Structures", "FAC104", "B-204"), ("Tue", "9:00", "Operating Systems", "FAC102", "B-101"), ("Wed", "11:00", "Mathematics III", "FAC103", "A-12"), ("Thu", "9:00", "Software Engg", "FAC104", "C-301")]:
            s.add(Lecture(day=day, slot=slot, subject=sub, faculty_id=fac, room=room))
        for t, u in [("Mid-semester examinations begin 2 December", True), ("Fee payment window closes 30 November", False), ("Annual technical fest registrations open", False)]:
            s.add(Notice(text=t, urgent=u, date=today()))
        s.add(Assignment(subject="DBMS", title="ER diagram and normalisation", due="2026-11-25", max_marks=20, created_by="FAC101"))
        s.commit()
seed()

class Login(BaseModel): id: str; password: str
@app.post("/api/login")
def login(b: Login, s: Session = Depends(get_db)):
    u = s.get(User, b.id.strip())
    if not u or not u.active or not check_pw(b.password, u.pw): raise HTTPException(401, "Wrong ID or password.")
    return {"token": jwt.encode({"sub": u.id, "exp": time.time() + 8 * 3600}, SECRET, algorithm="HS256"), "user": pub(u)}
@app.get("/api/me")
def me(u: User = Depends(current)): return pub(u)

def percent(s, sid):
    out = []
    for sub in SUBJECTS:
        rows = s.execute(select(Attendance.status).where(Attendance.student_id == sid, Attendance.subject == sub, Attendance.status.in_(["P", "A", "L"]))).scalars().all()
        out.append({"subject": sub, "percent": round(100 * sum(r in ("P", "L") for r in rows) / len(rows)) if rows else 0, "classes": len(rows)})
    return out
@app.get("/api/attendance/summary")
def summary(sid: Optional[str] = None, u: User = Depends(current), s: Session = Depends(get_db)):
    target = sid if (sid and u.role != "student") else u.id
    return percent(s, target)

class Rec(BaseModel): student_id: str; status: str
class Mark(BaseModel): subject: str; records: list[Rec]
def save_att(s, u, b: Mark, source):
    if b.subject not in SUBJECTS: raise HTTPException(400, "Unknown subject.")
    if s.scalar(select(Attendance.id).where(Attendance.date == today(), Attendance.subject == b.subject, Attendance.source == source).limit(1)):
        raise HTTPException(409, "Attendance for this subject is already submitted today.")
    for r in b.records:
        if r.status not in ("P", "A", "L", "PENDING") or not s.get(User, r.student_id): raise HTTPException(400, "Invalid record.")
        s.add(Attendance(date=today(), subject=b.subject, student_id=r.student_id, status=r.status, source=source, marked_by=u.id))
    log(s, u.id, f"{source} attendance {b.subject} ({len(b.records)} records)"); s.commit()
    return {"saved": len(b.records)}
@app.post("/api/attendance/manual")
def manual(b: Mark, u: User = Depends(need("faculty", "admin")), s: Session = Depends(get_db)): return save_att(s, u, b, "manual")

@app.post("/api/qr/start")
def qr_start(b: dict, u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    q = QRSession(subject=b.get("subject", ""), faculty_id=u.id, token=secrets.token_hex(3).upper(), expires=time.time() + 25)
    s.add(q); s.commit(); return {"id": q.id, "token": q.token, "subject": q.subject}
@app.post("/api/qr/{qid}/refresh")
def qr_refresh(qid: int, u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    q = s.get(QRSession, qid)
    if not q or q.faculty_id != u.id or not q.active: raise HTTPException(404, "Session ended.")
    q.token, q.expires = secrets.token_hex(3).upper(), time.time() + 25; s.commit()
    n = s.scalar(select(func.count()).select_from(Attendance).where(Attendance.date == today(), Attendance.subject == q.subject, Attendance.source == "qr"))
    return {"token": q.token, "count": n}
@app.post("/api/qr/{qid}/end")
def qr_end(qid: int, u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    q = s.get(QRSession, qid)
    if q and q.faculty_id == u.id: q.active = False; s.commit()
    return {"ended": True}
@app.post("/api/qr/scan")
def qr_scan(b: dict, u: User = Depends(need("student")), s: Session = Depends(get_db)):
    q = s.scalar(select(QRSession).where(QRSession.token == str(b.get("token", "")).upper(), QRSession.active == True))
    if not q or q.expires < time.time(): raise HTTPException(400, "Code is wrong or expired.")
    if s.scalar(select(Attendance.id).where(Attendance.date == today(), Attendance.subject == q.subject, Attendance.student_id == u.id, Attendance.source == "qr")):
        raise HTTPException(409, "Attendance already marked.")
    s.add(Attendance(date=today(), subject=q.subject, student_id=u.id, status="P", source="qr", marked_by=q.faculty_id)); s.commit()
    return {"subject": q.subject}

def identify_faces(image: bytes, roster: list[str]) -> dict:
    """PLUG-IN POINT: return {student_id: 'P'} for students you can verify (e.g. DeepFace / face_recognition,
    only with student consent and stored face encodings). Default: nobody is identified -> all PENDING."""
    return {}
@app.post("/api/photo/process")
async def photo_process(consent: bool = Form(...), photo: UploadFile = File(...), u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    if not consent: raise HTTPException(400, "Student consent is required.")
    data = await photo.read()
    if len(data) > 8_000_000 or not (photo.content_type or "").startswith("image/"): raise HTTPException(400, "Upload an image under 8 MB.")
    roster = s.execute(select(User.id, User.name).where(User.role == "student")).all()
    found = identify_faces(data, [r[0] for r in roster])  # photo itself is NOT stored
    return {"suggestions": [{"student_id": i, "name": n, "status": found.get(i, "PENDING")} for i, n in roster]}
@app.post("/api/photo/confirm")
def photo_confirm(b: Mark, u: User = Depends(need("faculty")), s: Session = Depends(get_db)): return save_att(s, u, b, "photo")

@app.get("/api/students")
def students(u: User = Depends(need("faculty", "admin")), s: Session = Depends(get_db)): return [pub(x) for x in s.scalars(select(User).where(User.role == "student"))]
@app.get("/api/faculty")
def faculty(u: User = Depends(need("admin")), s: Session = Depends(get_db)): return [pub(x) for x in s.scalars(select(User).where(User.role == "faculty"))]
class NewStudent(BaseModel): name: str; dept: str = "CSE"; sem: int = 1
@app.post("/api/students")
def add_student(b: NewStudent, u: User = Depends(need("admin")), s: Session = Depends(get_db)):
    n = s.scalar(select(func.count()).select_from(User).where(User.role == "student")) + 1
    sid = f"SVVV22{n:02d}"
    while s.get(User, sid): n += 1; sid = f"SVVV22{n:02d}"
    s.add(User(id=sid, name=b.name.strip(), role="student", pw=hash_pw("student123"), dept=b.dept, sem=b.sem, email=b.name.lower().replace(" ", ".") + "@svvv.edu.in"))
    log(s, u.id, f"added student {sid}"); s.commit(); return {"id": sid}

class NewAsg(BaseModel): subject: str; title: str; due: str; max_marks: int
@app.get("/api/assignments")
def assignments(u: User = Depends(current), s: Session = Depends(get_db)):
    out = []
    for a in s.scalars(select(Assignment).order_by(Assignment.id.desc())):
        d = {"id": a.id, "subject": a.subject, "title": a.title, "due": a.due, "max_marks": a.max_marks}
        if u.role == "student":
            sub = s.scalar(select(Submission).where(Submission.assignment_id == a.id, Submission.student_id == u.id))
            d["submission"] = sub and {"filename": sub.filename, "marks": sub.marks, "feedback": sub.feedback}
        else: d["submitted"] = s.scalar(select(func.count()).select_from(Submission).where(Submission.assignment_id == a.id))
        out.append(d)
    return out
@app.post("/api/assignments")
def new_asg(b: NewAsg, u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    s.add(Assignment(**b.model_dump(), created_by=u.id)); s.commit(); return {"ok": True}
@app.post("/api/assignments/{aid}/submit")
async def submit(aid: int, file: UploadFile = File(...), u: User = Depends(need("student")), s: Session = Depends(get_db)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in (".pdf", ".docx", ".pptx", ".zip"): raise HTTPException(400, "Allowed formats: PDF, DOCX, PPTX, ZIP.")
    data = await file.read()
    if len(data) > 10_000_000: raise HTTPException(400, "File is over 10 MB.")
    if s.scalar(select(Submission.id).where(Submission.assignment_id == aid, Submission.student_id == u.id)): raise HTTPException(409, "Already submitted.")
    stored = f"{aid}_{u.id}_{secrets.token_hex(4)}{ext}"; (UPLOADS / stored).write_bytes(data)
    s.add(Submission(assignment_id=aid, student_id=u.id, filename=file.filename, stored=stored)); s.commit(); return {"ok": True}
@app.get("/api/assignments/{aid}/submissions")
def subs(aid: int, u: User = Depends(need("faculty", "admin")), s: Session = Depends(get_db)):
    return [{"id": x.id, "student_id": x.student_id, "filename": x.filename, "marks": x.marks, "feedback": x.feedback} for x in s.scalars(select(Submission).where(Submission.assignment_id == aid))]
class Grade(BaseModel): marks: int; feedback: str = ""
@app.post("/api/submissions/{sid}/grade")
def grade(sid: int, b: Grade, u: User = Depends(need("faculty")), s: Session = Depends(get_db)):
    x = s.get(Submission, sid); a = x and s.get(Assignment, x.assignment_id)
    if not x or not (0 <= b.marks <= a.max_marks): raise HTTPException(400, f"Marks must be between 0 and {a and a.max_marks}.")
    x.marks, x.feedback = b.marks, b.feedback; s.commit(); return {"ok": True}

@app.get("/api/notices")
def notices(u: User = Depends(current), s: Session = Depends(get_db)): return [{"text": n.text, "urgent": n.urgent, "date": n.date} for n in s.scalars(select(Notice).order_by(Notice.id.desc()))]
class NewNotice(BaseModel): text: str; urgent: bool = False
@app.post("/api/notices")
def pub_notice(b: NewNotice, u: User = Depends(need("admin")), s: Session = Depends(get_db)):
    s.add(Notice(text=b.text, urgent=b.urgent, date=today())); log(s, u.id, "published notice"); s.commit(); return {"ok": True}
class NewTicket(BaseModel): category: str; message: str
@app.get("/api/tickets")
def tickets(u: User = Depends(current), s: Session = Depends(get_db)):
    q = select(Ticket) if u.role == "admin" else select(Ticket).where(Ticket.student_id == u.id)
    return [{"id": t.id, "student_id": t.student_id, "category": t.category, "message": t.message, "status": t.status} for t in s.scalars(q)]
@app.post("/api/tickets")
def new_ticket(b: NewTicket, u: User = Depends(need("student")), s: Session = Depends(get_db)):
    s.add(Ticket(student_id=u.id, category=b.category, message=b.message)); s.commit(); return {"ok": True}
@app.patch("/api/tickets/{tid}")
def set_ticket(tid: int, b: dict, u: User = Depends(need("admin")), s: Session = Depends(get_db)):
    t = s.get(Ticket, tid)
    if not t or b.get("status") not in ("Open", "In Progress", "Waiting for Student", "Resolved", "Closed"): raise HTTPException(400, "Invalid request.")
    t.status = b["status"]; s.commit(); return {"ok": True}

@app.get("/api/timetable")
def timetable(u: User = Depends(current), s: Session = Depends(get_db)):
    names = {x.id: x.name for x in s.scalars(select(User).where(User.role == "faculty"))}
    return [{"day": l.day, "slot": l.slot, "subject": l.subject, "faculty": names.get(l.faculty_id, l.faculty_id), "faculty_id": l.faculty_id, "room": l.room} for l in s.scalars(select(Lecture))]
class NewLecture(BaseModel): day: str; slot: str; subject: str; faculty_id: str; room: str
@app.post("/api/timetable")
def add_lecture(b: NewLecture, u: User = Depends(need("admin")), s: Session = Depends(get_db)):
    same = s.scalars(select(Lecture).where(Lecture.day == b.day, Lecture.slot == b.slot)).all()
    if any(l.faculty_id == b.faculty_id for l in same): raise HTTPException(409, "Conflict: faculty already teaches at this time.")
    if any(l.room == b.room for l in same): raise HTTPException(409, "Conflict: room already booked at this time.")
    s.add(Lecture(**b.model_dump())); log(s, u.id, "added lecture"); s.commit(); return {"ok": True}

@app.get("/api/analytics")
def analytics(u: User = Depends(need("faculty", "admin")), s: Session = Depends(get_db)):
    """Advisory only: simple attendance statistics. No grades or penalties are changed automatically."""
    st = s.scalars(select(User).where(User.role == "student")).all(); per = {x.id: percent(s, x.id) for x in st}
    low = [{"id": x.id, "name": x.name, "percent": round(sum(p["percent"] for p in per[x.id]) / len(SUBJECTS))} for x in st]
    return {"low_attendance": sorted([l for l in low if l["percent"] < 75], key=lambda l: l["percent"]),
            "subjects": sorted([{"subject": sub, "average": round(sum(per[i][k]["percent"] for i in per) / max(len(per), 1))} for k, sub in enumerate(SUBJECTS)], key=lambda x: x["average"])}
@app.get("/api/stats")
def stats(u: User = Depends(need("admin")), s: Session = Depends(get_db)):
    c = lambda r: s.scalar(select(func.count()).select_from(User).where(User.role == r))
    td = s.scalars(select(Attendance.status).where(Attendance.date == today())).all()
    return {"students": c("student"), "faculty": c("faculty"), "open_tickets": s.scalar(select(func.count()).select_from(Ticket).where(Ticket.status != "Closed")),
            "today_attendance": round(100 * td.count("P") / len(td)) if td else None}

app.mount("/", StaticFiles(directory=str(Path(__file__).resolve().parent.parent / "frontend"), html=True), name="web")
