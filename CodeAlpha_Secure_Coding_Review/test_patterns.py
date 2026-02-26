import re

test_code = '''
API_KEY = "sk-1234567890abcdef"
password = "admin123"
hash_md5 = hashlib.md5(password.encode()).hexdigest()
result = eval(user_input)
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
age = input("Enter your age: ")
'''

patterns = {
    'hardcoded_password': r'(password|passwd|pwd|pass|secret|key|token)\s*=\s*["\'][^"\']{3,}["\']',
    'eval_usage': r'\beval\s*\(',
    'weak_hashing': r'hashlib\s*\.\s*(md5|sha1)\s*\(',
    'sql_injection': r'(execute\s*\(\s*[fF]["\']|cursor\.execute\s*\(\s*[fF]["\']|["\'].*SELECT.*\{.*["\']|%.*%.*execute)',
    'missing_input_validation': r'^\s*[^#]*\binput\s*\(',
}

print("Testing patterns:\n")
for name, pattern in patterns.items():
    print(f"{name}:")
    for line in test_code.split('\n'):
        if re.search(pattern, line, re.IGNORECASE):
            print(f"  MATCH: {line.strip()}")
    print()
