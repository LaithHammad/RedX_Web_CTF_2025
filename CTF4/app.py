from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import hashlib
import unicodedata
import ipaddress
import secrets


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)



def init_db():
    conn = sqlite3.connect('redx.db')
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


    admin_password = hashlib.sha256('test'.encode()).hexdigest()
    print("DEBUG ADMIN HASH:", admin_password)
    try:
        cursor.execute("INSERT INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                       ('admin', admin_password, 'administrator', 'IT company', 'admin@redx.com'))
    except sqlite3.IntegrityError:
        pass


    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('sara', hashlib.sha256('Passw0rd'.encode()).hexdigest(), 'employee', 'Engineering', 'john.doe@techcorp.com'))
    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('jane.smith', hashlib.sha256('qwerty456'.encode()).hexdigest(), 'manager', 'Sales', 'jane.smith@techcorp.com'))
    cursor.execute("INSERT OR IGNORE INTO employees (username, password, role, department, email) VALUES (?, ?, ?, ?, ?)",
                  ('green', hashlib.sha256('blue'.encode()).hexdigest(), 'employee', 'Marketing', 'mike.wilson@techcorp.com'))
 
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
    conn = sqlite3.connect('redx.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO access_logs (username, ip_address, action) VALUES (?, ?, ?)", (username, ip, action))
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>RedX Employee Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #111; color: #eee; padding: 20px; }
        .container { max-width: 600px; margin: 50px auto; background: #1b1b1b; padding: 30px; border-radius: 8px; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin-bottom: 15px; border-radius: 4px; border: none; }
        .btn { padding: 10px 20px; background: #e74c3c; border: none; border-radius: 4px; color: #fff; cursor: pointer; width: 100%; }
        .btn:hover { background: #c0392b; } 
        h1 { text-align: center; margin-bottom: 25px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RedX Customers Portal</h1>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
<!---green:blue--->
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
        body { 
            font-family: Arial, sans-serif; 
            background-color: #111; 
            color: #eee; 
            padding: 20px; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            background: linear-gradient(135deg, #111 0%, #2a2a2a 100%); 
        }
        .container { 
            max-width: 600px; 
            margin: 50px auto; 
            background: #1b1b1b; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3); 
            animation: fadeIn 1s ease-in-out; 
        }
        .error { 
            color: #e74c3c; 
            text-align: center; 
        }
        .error h2 { 
            font-size: 2em; 
            margin-bottom: 15px; 
            text-transform: uppercase; 
            letter-spacing: 1px; 
        }
        .error p { 
            font-size: 1.1em; 
            opacity: 0.9; 
        }
        .back-link { 
            text-align: center; 
            margin-top: 20px; 
        }
        a { 
            color: #e74c3c; 
            text-decoration: none; 
            font-weight: bold; 
            transition: color 0.3s ease; 
        }
        a:hover { 
            color: #c0392b; 
            text-decoration: underline; 
        }
        @keyframes fadeIn { 
            from { opacity: 0; transform: translateY(-20px); } 
            to { opacity: 1; transform: translateY(0); } 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">
            <h2>Access Denied</h2>
            <p></p>
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
    
    conn = sqlite3.connect('redx.db')
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
    <title>RedX Employee Portal - Login Failed</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #111; color: #eee; padding: 20px; }
        .container { max-width: 600px; margin: 50px auto; background: #1b1b1b; padding: 30px; border-radius: 8px; }
        h2 { text-align: center; margin-bottom: 20px; }
        a { color: #e74c3c; text-decoration: none; }
        a:hover { text-decoration: underline; }
        p { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Login failed. Invalid credentials.</h2>
        <p><a href="/">Try Again</a></p>
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
        body {
            font-family: 'Inter', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a1a 0%, #2c2c2c 100%);
            color: #e0e0e0;
            margin: 0;
            padding: 40px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #222222;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
            animation: fadeIn 0.8s ease-in-out;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        h1 {
            font-size: 2.5em;
            color: #e74c3c;
            letter-spacing: 0.5px;
            font-weight: 700;
            margin: 0;
        }
        .nav {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .nav a {
            color: #e74c3c;
            text-decoration: none;
            font-size: 1.1em;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .nav a:hover {
            color: #c0392b;
            text-decoration: underline;
            transform: translateY(-2px);
        }
        .card {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            border-left: 4px solid #e74c3c;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            animation: fadeIn 1s ease-in-out;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
        }
        .card h3 {
            color: #e74c3c;
            font-size: 1.6em;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .card p {
            font-size: 1.1em;
            margin: 10px 0;
            line-height: 1.6;
            opacity: 0.9;
        }
        .logout {
            background: #e74c3c;
            color: #fff;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.3s ease;
        }
        .logout:hover {
            background: #c0392b;
            transform: translateY(-2px);
            text-decoration: none;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @media (max-width: 600px) {
            .container {
                padding: 20px;
            }
            h1 {
                font-size: 2em;
            }
            .nav {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            .nav a {
                font-size: 1em;
            }
            .card {
                margin: 10px 0;
            }
            .logout {
                padding: 6px 12px;
                font-size: 0.9em;
            }
        }
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
            {% if role == 'administrator' %}
            <a href="/admin">Admin Panel</a>
            {% endif %}
        </div>
        
        <div class="card">
            <h3>Latest Updates</h3>
            <p>Team meeting scheduled for Monday at 10 AM in Conference Room B</p>
            <p>Updated employee handbook now available in the portal</p>
        </div>
        
        <div class="card">
            <h3>Employee Tools</h3>
            <p>Access payroll, update profile, or request IT support</p>
        </div>
    </div>
</body>
</html>
    ''', username=session['username'], role=session['role'])


@app.route('/directory')
def directory():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    q = request.args.get('q', '').strip()

    conn = sqlite3.connect('redx.db')
    cursor = conn.cursor()

    
    if q:
        query = f"SELECT username, role, department, email FROM employees WHERE username LIKE '%{q}%' OR department LIKE '%{q}%' OR email LIKE '%{q}%'"
    else:
        query = "SELECT username, role, department, email FROM employees"

    cursor.execute(query)
    employees = cursor.fetchall()
    conn.close()

    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>RedX Employees Directory</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #111; color: #eee; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; background: #1b1b1b; padding: 30px; border-radius: 8px; }
        input[type=text] { padding: 10px; width: 300px; border-radius: 4px; border: none; margin-right: 10px; }
        .btn { padding: 10px 20px; background: #e74c3c; border: none; border-radius: 4px; color: #fff; cursor: pointer; }
        .btn:hover { background: #c0392b; }
        table { width: 100%; margin-top: 20px; border-collapse: collapse; }
        th, td { padding: 12px; border-bottom: 1px solid #333; text-align: left; }
        th { background: #222; }
        a { color: #e74c3c; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Customers Directory</h1>
        <form method="GET">
            <input type="text" name="q" placeholder="Search Customers..." value="{{ q }}">
            <button type="submit" class="btn">Search</button>
        </form>
        <table>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Department</th>
                <th>Email</th>
            </tr>
            {% for e in employees %}
            <tr>
                <td>{{ e[0] }}</td>
                <td>{{ e[1] }}</td>
                <td>{{ e[2] }}</td>
                <td>{{ e[3] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p><a href="/dashboard">&larr; Back to Dashboard</a></p>
    </div>
</body>
</html>
    ''', employees=employees, q=q)


@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'administrator':
        return redirect(url_for('index'))

    conn = sqlite3.connect('redx.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50")
    logs = cursor.fetchall()
    conn.close()

    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>RedX_Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #111; color: #eee; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: #1b1b1b; padding: 30px; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
        th { background: #222; }
        a { color: #e74c3c; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RedX Admin Panel</h1>
        <p> RedX{Adm1n_s0lI_DB_3qu4l_Fl4g}</p>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Username</th>
                <th>Action</th>
            </tr>
            {% for log in logs %}
            <tr>
                <td>{{ log[3] }}</td>
                <td>{{ log[1] }}</td>
                <td>{{ log[4] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p><a href="/dashboard">&larr; Back to Dashboard</a></p>
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
