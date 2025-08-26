import sqlite3
conn = sqlite3.connect("redx.db")
cursor = conn.cursor()
cursor.execute("SELECT username, password FROM employees WHERE username='admin'")
row = cursor.fetchone()
print("Stored admin password hash:", row[1])

