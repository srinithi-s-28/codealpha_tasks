================================================================================
SECURE CODING REVIEW TOOL - DOCUMENTATION
================================================================================

AIM:
----
To develop a simple Python-based security scanner that automatically detects 
common vulnerabilities in Python code and generates actionable security reports 
with remediation suggestions.

ALGORITHM:
----------
1. START
2. Initialize SecureCodeScanner with vulnerability patterns (regex-based)
3. Display menu with options:
   - Scan folder
   - View report
   - Exit
4. IF user selects "Scan folder":
   a. Accept folder path as input
   b. Recursively traverse all Python files (.py) in the folder
   c. For each file:
      - Read line by line
      - Match each line against vulnerability patterns:
        * Hardcoded passwords (password="...")
        * eval() usage
        * Weak hashing (MD5/SHA1)
        * SQL injection risks (string formatting in queries)
        * Missing input validation
      - Store detected vulnerabilities with metadata
   d. Generate security report with:
      - Vulnerability count
      - Severity level
      - File location and line number
      - Vulnerable code snippet
      - Suggested fix
5. IF user selects "View report":
   - Display the generated security report
6. IF user selects "Exit":
   - Terminate program
7. REPEAT until user exits
8. END

EXPLANATION:
------------
The Secure Coding Review Tool consists of:

1. SecureCodeScanner Class:
   - Stores vulnerability patterns as regex expressions
   - Each pattern includes severity, description, and fix suggestion
   - scan_file(): Scans individual Python files line by line
   - scan_folder(): Recursively scans all .py files in a directory
   - generate_report(): Creates a formatted text report

2. Vulnerability Detection Patterns:
   - Hardcoded Password: Detects password="value" patterns
   - eval() Usage: Finds dangerous eval() function calls
   - Weak Hashing: Identifies MD5/SHA1 usage
   - SQL Injection: Detects string formatting in SQL queries
   - Missing Validation: Finds input() without validation

3. Menu Interface:
   - Simple text-based UI for easy interaction
   - Options to scan, view reports, and exit

HOW TO RUN ON WINDOWS:
----------------------
Step 1: Ensure Python is installed
   - Open Command Prompt (cmd)
   - Type: python --version
   - If not installed, download from https://www.python.org/

Step 2: Navigate to the project folder
   - Open Command Prompt
   - Type: cd "c:\Users\srini\OneDrive\Desktop\secuirty coding review"

Step 3: Run the scanner
   - Type: python secure_code_scanner.py
   - Press Enter

Step 4: Use the tool
   - Select option 1 to scan a folder
   - Enter the folder path (e.g., test_project)
   - Select option 2 to view the generated report
   - Select option 3 to exit

SAMPLE OUTPUT:
--------------
==================================================
SECURE CODING REVIEW TOOL
==================================================
1. Scan folder
2. View report
3. Exit
==================================================
Enter your choice (1-3): 1
Enter folder path to scan: test_project

Scanning test_project...
Scan complete! Found 7 potential vulnerabilities.

Report generated: security_report.txt

==================================================
SECURE CODING REVIEW TOOL
==================================================
1. Scan folder
2. View report
3. Exit
==================================================
Enter your choice (1-3): 2

================================================================================
SECURE CODING REVIEW REPORT
================================================================================
Generated: 2024-01-15 10:30:45
Total Vulnerabilities Found: 7
================================================================================

[1] HIGH - Hardcoded password detected
File: test_project\vulnerable_code.py
Line: 7
Code: password = "admin123"
Fix: Use environment variables or secure vault (e.g., os.getenv("PASSWORD"))
--------------------------------------------------------------------------------

[2] HIGH - Hardcoded password detected
File: test_project\vulnerable_code.py
Line: 8
Code: db_password = 'mySecretPass'
Fix: Use environment variables or secure vault (e.g., os.getenv("PASSWORD"))
--------------------------------------------------------------------------------

[3] CRITICAL - Use of eval() function detected
File: test_project\vulnerable_code.py
Line: 12
Code: result = eval(user_input)
Fix: Avoid eval(). Use ast.literal_eval() for safe evaluation or json.loads() for JSON
--------------------------------------------------------------------------------

[4] MEDIUM - Weak hashing algorithm (MD5/SHA1) detected
File: test_project\vulnerable_code.py
Line: 15
Code: hash_md5 = hashlib.md5(b"data").hexdigest()
Fix: Use stronger algorithms like hashlib.sha256() or hashlib.sha512()
--------------------------------------------------------------------------------

[5] MEDIUM - Weak hashing algorithm (MD5/SHA1) detected
File: test_project\vulnerable_code.py
Line: 16
Code: hash_sha1 = hashlib.sha1(b"data").hexdigest()
Fix: Use stronger algorithms like hashlib.sha256() or hashlib.sha512()
--------------------------------------------------------------------------------

[6] CRITICAL - Potential SQL injection vulnerability
File: test_project\vulnerable_code.py
Line: 22
Code: query = f"SELECT * FROM users WHERE username = '{username}'"
Fix: Use parameterized queries with placeholders (e.g., cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)))
--------------------------------------------------------------------------------

[7] MEDIUM - Input without validation detected
File: test_project\vulnerable_code.py
Line: 26
Code: age = input("Enter your age: ")
Fix: Validate user input with type checking, length limits, and sanitization
--------------------------------------------------------------------------------

FEATURES:
---------
✓ Detects 5 common vulnerability types
✓ Provides severity ratings (CRITICAL, HIGH, MEDIUM)
✓ Shows exact file location and line numbers
✓ Displays vulnerable code snippets
✓ Suggests secure coding fixes
✓ Generates detailed text reports
✓ Simple menu-driven interface
✓ Beginner-friendly code structure

LIMITATIONS:
------------
- Pattern-based detection (may have false positives/negatives)
- Does not execute code (static analysis only)
- Limited to Python files
- Basic regex patterns (not comprehensive)

FUTURE ENHANCEMENTS:
--------------------
- Add more vulnerability patterns
- Support for other languages
- HTML/PDF report generation
- Integration with CI/CD pipelines
- Configuration file for custom rules
