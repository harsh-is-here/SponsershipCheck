import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())

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
        stats = {
            'total_members': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member'").values())[0],
            'online_members': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member' AND is_online=1").values())[0],
            'total_companies': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM companies").values())[0],
            'total_assignments': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments").values())[0],
            'total_emails_sent': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs").values())[0],
        }
        return render_template('admin_dashboard.html', members=members,
                               companies=companies, assignments=all_assignments, stats=stats)
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
        stats = {
            'total_assigned': len(assignments),
            'emails_sent': list(db_fetchone(db,
                "SELECT COUNT(*) as cnt FROM email_logs WHERE user_id=?", (user_id,)
            ).values())[0],
            'pending': sum(1 for a in assignments if a['emails_sent'] == 0),
        }
        return render_template('member_dashboard.html', assignments=assignments, stats=stats)


# --------------- Company CRUD (Admin) ---------------

@app.route('/companies/add', methods=['POST'])
@admin_required
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
    db_execute(db,
        "INSERT INTO companies (name, email, industry, website, notes) VALUES (?,?,?,?,?)",
        (name, email, industry, website, notes)
    )
    db.commit()
    flash(f'Company "{name}" added!', 'success')
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


# --------------- Assignments (Admin) ---------------

@app.route('/assign', methods=['POST'])
@admin_required
def assign_company():
    user_id = request.form.get('user_id', type=int)
    company_id = request.form.get('company_id', type=int)
    if not user_id or not company_id:
        flash('Select both a member and a company.', 'danger')
        return redirect(url_for('dashboard'))
    db = get_db()
    try:
        db_execute(db,
            "INSERT INTO assignments (user_id, company_id, assigned_by) VALUES (?,?,?)",
            (user_id, company_id, session['user_id'])
        )
        db.commit()
        flash('Company assigned successfully!', 'success')
    except (sqlite3.IntegrityError, Exception) as e:
        db.rollback()
        flash('This company is already assigned to that member.', 'warning')
    return redirect(url_for('dashboard'))


@app.route('/unassign/<int:assignment_id>', methods=['POST'])
@admin_required
def unassign_company(assignment_id):
    db = get_db()
    db_execute(db, "DELETE FROM email_logs WHERE assignment_id=?", (assignment_id,))
    db_execute(db, "DELETE FROM assignments WHERE id=?", (assignment_id,))
    db.commit()
    flash('Assignment removed.', 'info')
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
    return jsonify([dict(u) for u in users])


@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    if session['role'] == 'admin':
        return jsonify({
            'online': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM users WHERE role='member' AND is_online=1").values())[0],
            'total_emails': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs").values())[0],
            'total_assignments': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments").values())[0],
        })
    else:
        uid = session['user_id']
        return jsonify({
            'total_assigned': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM assignments WHERE user_id=?", (uid,)).values())[0],
            'emails_sent': list(db_fetchone(db, "SELECT COUNT(*) as cnt FROM email_logs WHERE user_id=?", (uid,)).values())[0],
        })


init_db()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=False)
