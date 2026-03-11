import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
DATABASE = os.path.join(os.path.dirname(__file__), 'sponsorship.db')

# --------------- Database helpers ---------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',  -- 'admin' or 'member'
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
            status TEXT DEFAULT 'sent',  -- 'sent', 'replied', 'no_response'
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (assignment_id) REFERENCES assignments(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (company_id) REFERENCES companies(id)
        );
    """)
    # Create default admin if not exists
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
        db.execute(
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
    db.execute("UPDATE users SET is_online=0 WHERE last_active < ?", (cutoff,))
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
        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            db.execute(
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
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'member')",
                (username, generate_password_hash(password))
            )
            db.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    db = get_db()
    db.execute("UPDATE users SET is_online=0 WHERE id=?", (session['user_id'],))
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
        members = db.execute(
            "SELECT * FROM users WHERE role='member' ORDER BY is_online DESC, username"
        ).fetchall()
        companies = db.execute("SELECT * FROM companies ORDER BY name").fetchall()
        all_assignments = db.execute("""
            SELECT a.*, u.username, c.name as company_name, c.email as company_email,
                   c.industry, assigner.username as assigned_by_name,
                   (SELECT COUNT(*) FROM email_logs el WHERE el.assignment_id=a.id) as emails_sent
            FROM assignments a
            JOIN users u ON a.user_id = u.id
            JOIN companies c ON a.company_id = c.id
            JOIN users assigner ON a.assigned_by = assigner.id
            ORDER BY a.assigned_at DESC
        """).fetchall()
        stats = {
            'total_members': db.execute("SELECT COUNT(*) FROM users WHERE role='member'").fetchone()[0],
            'online_members': db.execute("SELECT COUNT(*) FROM users WHERE role='member' AND is_online=1").fetchone()[0],
            'total_companies': db.execute("SELECT COUNT(*) FROM companies").fetchone()[0],
            'total_assignments': db.execute("SELECT COUNT(*) FROM assignments").fetchone()[0],
            'total_emails_sent': db.execute("SELECT COUNT(*) FROM email_logs").fetchone()[0],
        }
        return render_template('admin_dashboard.html', members=members,
                               companies=companies, assignments=all_assignments, stats=stats)
    else:
        # Member sees their own assignments
        assignments = db.execute("""
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
        """, (user_id,)).fetchall()
        stats = {
            'total_assigned': len(assignments),
            'emails_sent': db.execute(
                "SELECT COUNT(*) FROM email_logs WHERE user_id=?", (user_id,)
            ).fetchone()[0],
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
    db.execute(
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
    db.execute("DELETE FROM email_logs WHERE company_id=?", (company_id,))
    db.execute("DELETE FROM assignments WHERE company_id=?", (company_id,))
    db.execute("DELETE FROM companies WHERE id=?", (company_id,))
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
        db.execute(
            "INSERT INTO assignments (user_id, company_id, assigned_by) VALUES (?,?,?)",
            (user_id, company_id, session['user_id'])
        )
        db.commit()
        flash('Company assigned successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('This company is already assigned to that member.', 'warning')
    return redirect(url_for('dashboard'))


@app.route('/unassign/<int:assignment_id>', methods=['POST'])
@admin_required
def unassign_company(assignment_id):
    db = get_db()
    db.execute("DELETE FROM email_logs WHERE assignment_id=?", (assignment_id,))
    db.execute("DELETE FROM assignments WHERE id=?", (assignment_id,))
    db.commit()
    flash('Assignment removed.', 'info')
    return redirect(url_for('dashboard'))


# --------------- Email Logging (Members) ---------------

@app.route('/mark-email-sent/<int:assignment_id>', methods=['POST'])
@login_required
def mark_email_sent(assignment_id):
    db = get_db()
    assignment = db.execute(
        "SELECT * FROM assignments WHERE id=? AND user_id=?",
        (assignment_id, session['user_id'])
    ).fetchone()
    if not assignment:
        flash('Assignment not found.', 'danger')
        return redirect(url_for('dashboard'))
    notes = request.form.get('notes', '').strip()
    status = request.form.get('status', 'sent')
    db.execute(
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
    users = db.execute(
        "SELECT id, username, is_online, last_active FROM users WHERE role='member' ORDER BY is_online DESC"
    ).fetchall()
    return jsonify([dict(u) for u in users])


@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    if session['role'] == 'admin':
        return jsonify({
            'online': db.execute("SELECT COUNT(*) FROM users WHERE role='member' AND is_online=1").fetchone()[0],
            'total_emails': db.execute("SELECT COUNT(*) FROM email_logs").fetchone()[0],
            'total_assignments': db.execute("SELECT COUNT(*) FROM assignments").fetchone()[0],
        })
    else:
        uid = session['user_id']
        return jsonify({
            'total_assigned': db.execute("SELECT COUNT(*) FROM assignments WHERE user_id=?", (uid,)).fetchone()[0],
            'emails_sent': db.execute("SELECT COUNT(*) FROM email_logs WHERE user_id=?", (uid,)).fetchone()[0],
        })


if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=10000, debug=False)
