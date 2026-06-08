import sqlite3

# Connect to the database
conn = sqlite3.connect('mycustomdb.sqlite3')
cursor = conn.cursor()

# Get all users
cursor.execute("SELECT username, email, is_superuser, is_staff FROM auth_user;")
users = cursor.fetchall()

print("Users in the database:")
for user in users:
    print(f"Username: {user[0]}, Email: {user[1]}, Superuser: {user[2]}, Staff: {user[3]}")

# Close the connection
conn.close()