import hashlib
import sqlite3

# Hardcoded credentials (Vulnerability 1 & 2)
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"

# Weak hashing (Vulnerability 2)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Using eval (Vulnerability 3)
def calculate(user_input):
    return eval(user_input)

# SQL Injection risk (Vulnerability 4)
def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

# Missing input validation (Vulnerability 5)
def get_user_age():
    age = input("Enter your age: ")
    print("Your age is:", age)

if __name__ == "__main__":
    user_input = input("Enter calculation: ")
    print("Result:", calculate(user_input))
