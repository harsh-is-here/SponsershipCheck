import os
import sqlite3
import base64
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g, send_file, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())

@app.template_filter('datefmt')
def datefmt_filter(value, fmt='%Y-%m-%d %H:%M'):
    if value is None:
        return '-'
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return value[:16] if len(value) > 16 else value
    return value.strftime(fmt)

DATABASE_URL = os.environ.get('DATABASE_URL')
# Render uses postgres:// but psycopg2 needs postgresql://
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

USE_POSTGRES = DATABASE_URL is not None
SQLITE_PATH = os.path.join(os.path.dirname(__file__), 'sponsorship.db')

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

# --------------- Database helpers ---------------

def get_db():
    if 'db' not in g:
        if USE_POSTGRES:
            g.db = psycopg2.connect(DATABASE_URL)
            g.db.autocommit = False
        else:
            g.db = sqlite3.connect(SQLITE_PATH)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def db_execute(db, query, params=None):
    """Execute a query, adapting placeholders for PostgreSQL."""
    if USE_POSTGRES:
        query = query.replace('?', '%s')
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = db.cursor()
    cur.execute(query, params or ())
    return cur


def db_fetchone(db, query, params=None):
    cur = db_execute(db, query, params)
    row = cur.fetchone()
    cur.close()
    return row


def db_fetchall(db, query, params=None):
    cur = db_execute(db, query, params)
    rows = cur.fetchall()
    cur.close()
    return rows


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                last_active TIMESTAMP,
                is_online INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                industry TEXT,
                website TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assignments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                company_id INTEGER NOT NULL REFERENCES companies(id),
                assigned_by INTEGER NOT NULL REFERENCES users(id),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, company_id)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_logs (
                id SERIAL PRIMARY KEY,
                assignment_id INTEGER NOT NULL REFERENCES assignments(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                company_id INTEGER NOT NULL REFERENCES companies(id),
                status TEXT DEFAULT 'sent',
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                mimetype TEXT NOT NULL,
                data BYTEA NOT NULL,
                uploaded_by INTEGER NOT NULL REFERENCES users(id),
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("SELECT id FROM users WHERE role='admin'")
        existing = cur.fetchone()
        if not existing:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                ('admin', generate_password_hash('@MMMUTadmin123'), 'admin')
            )
        conn.commit()
        cur.close()
        conn.close()
    else:
        db = sqlite3.connect(SQLITE_PATH)
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                last_active TIMESTAMP,
                is_online INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                industry TEXT,
                website TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                company_id INTEGER NOT NULL,
                assigned_by INTEGER NOT NULL,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (company_id) REFERENCES companies(id),
                FOREIGN KEY (assigned_by) REFERENCES users(id),
                UNIQUE(user_id, company_id)
            );

            CREATE TABLE IF NOT EXISTS email_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                company_id INTEGER NOT NULL,
                status TEXT DEFAULT 'sent',
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (assignment_id) REFERENCES assignments(id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                mimetype TEXT NOT NULL,
                data BLOB NOT NULL,
                uploaded_by INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users(id)
            );
        """)
        existing = db.execute("SELECT id FROM users WHERE role='admin'").fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ('admin', generate_password_hash('@MMMUTadmin123'), 'admin')
            )
        db.commit()
        db.close()


# --------------- Auth helpers ---------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def update_activity():
    if 'user_id' in session:
        db = get_db()
        db_execute(db,
            "UPDATE users SET last_active=?, is_online=1 WHERE id=?",
            (datetime.now().isoformat(), session['user_id'])
        )
        db.commit()


@app.before_request
def before_request_func():
    update_activity()
    # Mark users offline if inactive > 5 minutes
    db = get_db()
    cutoff = (datetime.now() - timedelta(minutes=5)).isoformat()
    db_execute(db, "UPDATE users SET is_online=0 WHERE last_active < ?", (cutoff,))
    db.commit()


# --------------- Routes ---------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        db = get_db()
        user = db_fetchone(db,
            "SELECT * FROM users WHERE username=?",
            (username,)
        )
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            db_execute(db,
                "UPDATE users SET is_online=1, last_active=? WHERE id=?",
                (datetime.now().isoformat(), user['id'])
            )
            db.commit()
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        db = get_db()
        try:
            db_execute(db,
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'member')",
                (username, generate_password_hash(password))
            )
            db.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except (sqlite3.IntegrityError, Exception) as e:
            db.rollback()
            flash('Username already exists.', 'danger')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    db = get_db()
    db_execute(db, "UPDATE users SET is_online=0 WHERE id=?", (session['user_id'],))
    db.commit()
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_id = session['user_id']
    role = session['role']

    if role == 'admin':
        # Admin sees everything
        members = db_fetchall(db,
            "SELECT * FROM users WHERE role='member' ORDER BY is_online DESC, username"
        )
        companies = db_fetchall(db, "SELECT * FROM companies ORDER BY name")
        all_assignments = db_fetchall(db, """
            SELECT a.*, u.username, c.name as company_name, c.email as company_email,
                   c.industry, assigner.username as assigned_by_name,
                   (SELECT COUNT(*) FROM email_logs el WHERE el.assignment_id=a.id) as emails_sent
            FROM assignments a
            JOIN users u ON a.user_id = u.id
            JOIN companies c ON a.company_id = c.id
            JOIN users assigner ON a.assigned_by = assigner.id
            ORDER BY a.assigned_at DESC
        """)
        email_logs = db_fetchall(db, """
            SELECT el.*, u.username, c.name as company_name, c.email as company_email
            FROM email_logs el
            JOIN users u ON el.user_id = u.id
            JOIN companies c ON el.company_id = c.id
            ORDER BY el.sent_at DESC
        """)
        documents = db_fetchall(db, """
            SELECT d.id, d.filename, d.mimetype, d.uploaded_at, u.username as uploaded_by_name
            FROM documents d
            JOIN users u ON d.uploaded_by = u.id
            ORDER BY d.uploaded_at DESC
        """)
        stats = {
            'total_members': db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member'")['cnt'],
            'online_members': db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member' AND is_online=1")['cnt'],
            'total_companies': db_fetchone(db, "SELECT COUNT(*) as cnt FROM companies")['cnt'],
            'total_assignments': db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments")['cnt'],
            'total_emails_sent': db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs")['cnt'],
        }
        return render_template('admin_dashboard.html', members=members,
                               companies=companies, assignments=all_assignments,
                               email_logs=email_logs, documents=documents, stats=stats)
    else:
        # Member sees their own assignments
        assignments = db_fetchall(db, """
            SELECT a.*, c.name as company_name, c.email as company_email,
                   c.industry, c.website,
                   assigner.username as assigned_by_name,
                   (SELECT COUNT(*) FROM email_logs el WHERE el.assignment_id=a.id) as emails_sent,
                   (SELECT MAX(el.sent_at) FROM email_logs el WHERE el.assignment_id=a.id) as last_email_at
            FROM assignments a
            JOIN companies c ON a.company_id = c.id
            JOIN users assigner ON a.assigned_by = assigner.id
            WHERE a.user_id = ?
            ORDER BY a.assigned_at DESC
        """, (user_id,))
        # Available companies = not assigned to anyone
        available_companies = db_fetchall(db, """
            SELECT c.* FROM companies c
            WHERE c.id NOT IN (SELECT company_id FROM assignments)
            ORDER BY c.name
        """)
        email_logs = db_fetchall(db, """
            SELECT el.*, c.name as company_name, c.email as company_email
            FROM email_logs el
            JOIN companies c ON el.company_id = c.id
            WHERE el.user_id = ?
            ORDER BY el.sent_at DESC
        """, (user_id,))
        documents = db_fetchall(db, """
            SELECT d.id, d.filename, d.mimetype, d.uploaded_at, u.username as uploaded_by_name
            FROM documents d
            JOIN users u ON d.uploaded_by = u.id
            ORDER BY d.uploaded_at DESC
        """)
        stats = {
            'total_assigned': len(assignments),
            'emails_sent': db_fetchone(db,
                "SELECT COUNT(*) as cnt FROM email_logs WHERE user_id=?", (user_id,)
            )['cnt'],
            'pending': sum(1 for a in assignments if a['emails_sent'] == 0),
        }
        return render_template('member_dashboard.html', assignments=assignments,
                               available_companies=available_companies,
                               email_logs=email_logs, documents=documents, stats=stats)


# --------------- Company CRUD (Members add, Admin deletes) ---------------

@app.route('/companies/add', methods=['POST'])
@login_required
def add_company():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    industry = request.form.get('industry', '').strip()
    website = request.form.get('website', '').strip()
    notes = request.form.get('notes', '').strip()
    if not name:
        flash('Company name is required.', 'danger')
        return redirect(url_for('dashboard'))
    db = get_db()
    # Check if company already exists
    existing = db_fetchone(db, "SELECT id FROM companies WHERE LOWER(name)=LOWER(?)", (name,))
    if existing:
        flash(f'Company "{name}" already exists.', 'warning')
        return redirect(url_for('dashboard'))
    db_execute(db,
        "INSERT INTO companies (name, email, industry, website, notes) VALUES (?,?,?,?,?)",
        (name, email, industry, website, notes)
    )
    # Get the new company id
    new_company = db_fetchone(db, "SELECT id FROM companies WHERE LOWER(name)=LOWER(?)", (name,))
    # Auto-assign to the member who added it
    if session['role'] == 'member':
        db_execute(db,
            "INSERT INTO assignments (user_id, company_id, assigned_by) VALUES (?,?,?)",
            (session['user_id'], new_company['id'], session['user_id'])
        )
    db.commit()
    flash(f'Company "{name}" added and assigned to you!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/companies/select/<int:company_id>', methods=['POST'])
@login_required
def select_company(company_id):
    """Member selects an available (unassigned) company."""
    db = get_db()
    # Check company exists and is not already assigned
    company = db_fetchone(db, "SELECT * FROM companies WHERE id=?", (company_id,))
    if not company:
        flash('Company not found.', 'danger')
        return redirect(url_for('dashboard'))
    already_assigned = db_fetchone(db, "SELECT id FROM assignments WHERE company_id=?", (company_id,))
    if already_assigned:
        flash('This company is already taken by another user.', 'warning')
        return redirect(url_for('dashboard'))
    db_execute(db,
        "INSERT INTO assignments (user_id, company_id, assigned_by) VALUES (?,?,?)",
        (session['user_id'], company_id, session['user_id'])
    )
    db.commit()
    flash(f'Company "{company["name"]}" assigned to you!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/companies/delete/<int:company_id>', methods=['POST'])
@admin_required
def delete_company(company_id):
    db = get_db()
    db_execute(db, "DELETE FROM email_logs WHERE company_id=?", (company_id,))
    db_execute(db, "DELETE FROM assignments WHERE company_id=?", (company_id,))
    db_execute(db, "DELETE FROM companies WHERE id=?", (company_id,))
    db.commit()
    flash('Company deleted.', 'info')
    return redirect(url_for('dashboard'))


# --------------- Assignments (Admin can unassign) ---------------

@app.route('/unassign/<int:assignment_id>', methods=['POST'])
@admin_required
def unassign_company(assignment_id):
    db = get_db()
    db_execute(db, "DELETE FROM email_logs WHERE assignment_id=?", (assignment_id,))
    db_execute(db, "DELETE FROM assignments WHERE id=?", (assignment_id,))
    db.commit()
    flash('Assignment removed.', 'info')
    return redirect(url_for('dashboard'))


# --------------- User Management (Admin) ---------------

@app.route('/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    user = db_fetchone(db, "SELECT * FROM users WHERE id=? AND role='member'", (user_id,))
    if not user:
        flash('Member not found.', 'danger')
        return redirect(url_for('dashboard'))
    # Delete user's email logs, assignments, then the user
    db_execute(db, "DELETE FROM email_logs WHERE user_id=?", (user_id,))
    db_execute(db, "DELETE FROM assignments WHERE user_id=?", (user_id,))
    db_execute(db, "DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash(f'User "{user["username"]}" deleted.', 'info')
    return redirect(url_for('dashboard'))


# --------------- Document Management (Admin uploads, all view) ---------------

ALLOWED_EXTENSIONS = {'pdf', 'xlsx', 'xls', 'csv'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

@app.route('/documents/upload', methods=['POST'])
@admin_required
def upload_document():
    if 'file' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        flash('Only PDF, Excel (.xlsx, .xls), and CSV files are allowed.', 'danger')
        return redirect(url_for('dashboard'))
    data = file.read()
    if len(data) > MAX_FILE_SIZE:
        flash('File too large. Maximum 10 MB.', 'danger')
        return redirect(url_for('dashboard'))
    db = get_db()
    db_execute(db,
        "INSERT INTO documents (filename, mimetype, data, uploaded_by) VALUES (?,?,?,?)",
        (filename, file.content_type, data, session['user_id'])
    )
    db.commit()
    flash(f'Document "{filename}" uploaded!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/documents/download/<int:doc_id>')
@login_required
def download_document(doc_id):
    db = get_db()
    doc = db_fetchone(db, "SELECT * FROM documents WHERE id=?", (doc_id,))
    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('dashboard'))
    return Response(
        doc['data'],
        mimetype=doc['mimetype'],
        headers={'Content-Disposition': f'attachment; filename="{doc["filename"]}"'}
    )


@app.route('/documents/delete/<int:doc_id>', methods=['POST'])
@admin_required
def delete_document(doc_id):
    db = get_db()
    db_execute(db, "DELETE FROM documents WHERE id=?", (doc_id,))
    db.commit()
    flash('Document deleted.', 'info')
    return redirect(url_for('dashboard'))


# --------------- Email Logging (Members) ---------------

@app.route('/mark-email-sent/<int:assignment_id>', methods=['POST'])
@login_required
def mark_email_sent(assignment_id):
    db = get_db()
    assignment = db_fetchone(db,
        "SELECT * FROM assignments WHERE id=? AND user_id=?",
        (assignment_id, session['user_id'])
    )
    if not assignment:
        flash('Assignment not found.', 'danger')
        return redirect(url_for('dashboard'))
    notes = request.form.get('notes', '').strip()
    status = request.form.get('status', 'sent')
    db_execute(db,
        "INSERT INTO email_logs (assignment_id, user_id, company_id, status, notes) VALUES (?,?,?,?,?)",
        (assignment_id, session['user_id'], assignment['company_id'], status, notes)
    )
    db.commit()
    flash('Email status updated!', 'success')
    return redirect(url_for('dashboard'))


# --------------- API endpoints for live updates ---------------

@app.route('/api/online-users')
@admin_required
def api_online_users():
    db = get_db()
    users = db_fetchall(db,
        "SELECT id, username, is_online, last_active FROM users WHERE role='member' ORDER BY is_online DESC"
    )
    result = []
    for u in users:
        d = dict(u)
        if d.get('last_active') and not isinstance(d['last_active'], str):
            d['last_active'] = d['last_active'].isoformat()
        result.append(d)
    return jsonify(result)


@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    if session['role'] == 'admin':
        return jsonify({
            'online': db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member' AND is_online=1")['cnt'],
            'total_emails': db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs")['cnt'],
            'total_assignments': db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments")['cnt'],
        })
    else:
        uid = session['user_id']
        return jsonify({
            'total_assigned': db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments WHERE user_id=?", (uid,))['cnt'],
            'emails_sent': db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs WHERE user_id=?", (uid,))['cnt'],
        })


try:
    init_db()
except Exception as e:
    print(f"WARNING: init_db failed: {e}")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=False)
