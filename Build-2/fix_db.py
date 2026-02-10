import os
import mysql.connector

conn = mysql.connector.connect(
    host=os.getenv("MYSQLHOST"),
    user=os.getenv("MYSQLUSER"),
    password=os.getenv("MYSQLPASSWORD"),
    database=os.getenv("MYSQLDATABASE"),
    port=int(os.getenv("MYSQLPORT"))
)

cursor = conn.cursor()

# delete old table
cursor.execute("DROP TABLE IF EXISTS users")

# create new correct table
cursor.execute("""
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255)
)
""")

conn.commit()
cursor.close()
conn.close()

print("✅ Done. Table fixed.")
