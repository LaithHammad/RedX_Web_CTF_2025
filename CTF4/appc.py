from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import hashlib
import unicodedata
import ipaddress
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

def init_db():
    conn = sqlite3.connect('company.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT,
            email TEXT,
            active INTEGER DEFAULT 1
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT
        )
    ''')
    
    admin_password = hashlib.sha256('SuperPassword'.encode()).hexdigest()
    
    try:
        cursor.execute("INSERT INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                      ('admin', admin_password, 'administrator', 'IT Security', 'admin@techcorp.com'))
    except sqlite3.IntegrityError:
        pass
    
    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('sara', hashlib.sha256('password123'.encode()).hexdigest(), 'employee', 'Engineering', 'john.doe@techcorp.com'))
    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('jane.smith', hashlib.sha256('qwerty456'.encode()).hexdigest(), 'manager', 'Sales', 'jane.smith@techcorp.com'))
    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('test', hashlib.sha256('test123'.encode()).hexdigest(), 'employee', 'Marketing', 'mike.wilson@techcorp.com'))
    
    conn.commit()
    conn.close()

def normalize_input(text):
    return unicodedata.normalize('NFKC', text)

def is_localhost(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback
    except:
        return False

def log_access(username, ip, action):
    conn = sqlite3.connect('company.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO access_logs (username, ip_address, action) VALUES (?, ?, ?)",
                  (username, ip, action))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>TechCorp Employee Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .login-form { max-width: 400px; margin: 0 auto; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        .btn { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; width: 100%; }
        .btn:hover { background-color: #0056b3; }
        .error { color: red; margin-top: 10px; text-align: center; }
        .features { margin-top: 30px; }
        .feature { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>TechCorp Employee Portal</h1>
        <div class="login-form">
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Employee ID:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
        </div>
        
        <div class="features">
            <!-- <h2>Default Marketing creds : test:test123</h2> -->
            <h3>Portal Features:</h3>
            <div class="feature">
                <strong>Employee Directory</strong> - Search and view employee information
            </div>
            <div class="feature">
                <strong>Time Management</strong> - Clock in/out and view timesheets
            </div>
            <div class="feature">
                <strong>Benefits Portal</strong> - Manage health insurance and retirement plans
            </div>
            <div class="feature">
                <strong>Administrative Tools</strong> - For authorized personnel only
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 TechCorp Industries. All rights reserved.</p>
            <p>For technical support, contact IT at ext. 4201</p>
        </div>
    </div>
</body>
</html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
    
    if username == 'admin' and not is_localhost(client_ip):
        log_access(username, client_ip, 'blocked_admin_access')
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error { color: #d32f2f; text-align: center; }
        .back-link { text-align: center; margin-top: 20px; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">
            <h2>Access Denied</h2>
            <p>(admin) user access is restricted to localhost connections only.</p>
            <p>Your IP: {{ client_ip }}</p>
        </div>
        <div class="back-link">
            <a href="/">Return to Login</a>
        </div>
    </div>
</body>
</html>
        ''', client_ip=client_ip)
    
    if not username or not password:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('company.db')
    cursor = conn.cursor()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    normalized_username = normalize_input(username)
    
    query = "SELECT * FROM employees WHERE username = ? AND password = ? AND active = 1"
    cursor.execute(query, (normalized_username, password_hash))
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[3]
        log_access(username, client_ip, 'successful_login')
        conn.close()
        return redirect(url_for('dashboard'))
    else:
        log_access(username, client_ip, 'failed_login')
        conn.close()
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Login Failed</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error { color: #d32f2f; text-align: center; }
        .back-link { text-align: center; margin-top: 20px; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">
            <h2>Login Failed</h2>
            <p>Invalid credentials. Please check your employee ID and password.</p>
        </div>
        <div class="back-link">
            <a href="/">Try Again</a>
        </div>
    </div>
</body>
</html>
        ''')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Employee Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .nav { background: #343a40; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
        .card { background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 4px; border-left: 4px solid #007bff; }
        .logout { background-color: #dc3545; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome, {{ username }}!</h1>
            <a href="/logout" class="logout">Logout</a>
        </div>
        
        <div class="nav">
            <a href="/directory">Employee Directory</a>
            <a href="/timesheet">My Timesheet</a>
            <a href="/benefits">Benefits</a>
            {% if role == 'administrator' %}
            <a href="/admin">Admin Panel</a>
            {% endif %}
        </div>
        
        <div class="card">
            <h3>Recent Announcements</h3>
            <p>Company picnic scheduled for next Friday at Central Park</p>
            <p>New security protocols effective immediately</p>
        </div>
        
        <div class="card">
            <h3>Quick Actions</h3>
            <p>Clock in/out, submit expense reports, request time off</p>
        </div>
    </div>
</body>
</html>
    ''', username=session['username'], role=session['role'])

@app.route('/directory')
def directory():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    search = request.args.get('search', '').strip()
    
    conn = sqlite3.connect('company.db')
    cursor = conn.cursor()
    
    if search:
        query = f"SELECT username, role, department, email FROM employees WHERE (username LIKE '%{search}%' OR department LIKE '%{search}%' OR email LIKE '%{search}%') AND active = 1"
    else:
        query = "SELECT username, role, department, email FROM employees WHERE active = 1"
    
    cursor.execute(query)
    employees = cursor.fetchall()
    conn.close()
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Employee Directory</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .search-form { margin-bottom: 20px; }
        input[type="text"] { padding: 10px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }
        .btn { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .back-link { margin-bottom: 20px; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/dashboard">&larr; Back to Dashboard</a>
        </div>
        
        <h2>Employee Directory</h2>
        
        <form method="GET" class="search-form">
            <input type="text" name="search" placeholder="Search employees..." value="{{ search }}">
            <button type="submit" class="btn">Search</button>
        </form>
        
        <table>
            <thead>
                <tr>
                    <th>Employee ID</th>
                    <th>Role</th>
                    <th>Department</th>
                    <th>Email</th>
                </tr>
            </thead>
            <tbody>
                {% for employee in employees %}
                <tr>
                    <td>{{ employee[0] }}</td>
                    <td>{{ employee[1] }}</td>
                    <td>{{ employee[2] }}</td>
                    <td>{{ employee[3] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
    ''', employees=employees, search=search)

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'administrator':
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('company.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50")
    logs = cursor.fetchall()
    conn.close()
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }
        th { background-color: #f8f9fa; }
        .back-link { margin-bottom: 20px; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/dashboard">&larr; Back to Dashboard</a>
        </div>
        
        <h2>System Administration</h2>
        
        <p>Welcome NCSC{26b38e8433a01890c94832f137205f25}</p>
        <h3>Recent Access Logs</h3>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Username</th>
                    <th>IP Address</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr>
                    <td>{{ log[3] }}</td>
                    <td>{{ log[1] }}</td>
                    <td>{{ log[2] }}</td>
                    <td>{{ log[4] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
    ''', logs=logs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)