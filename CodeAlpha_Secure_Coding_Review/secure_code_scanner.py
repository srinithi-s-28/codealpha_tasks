import os
import re
from datetime import datetime

class SecureCodeScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.patterns = {
            'hardcoded_password': {
                'regex': r'(password|passwd|pwd|pass|secret|key|token)\s*=\s*["\'][^"\']{3,}["\']',
                'severity': 'HIGH',
                'description': 'Hardcoded password detected',
                'fix': 'Use environment variables or secure vault (e.g., os.getenv("PASSWORD"))'
            },
            'eval_usage': {
                'regex': r'\beval\s*\(',
                'severity': 'CRITICAL',
                'description': 'Use of eval() function detected',
                'fix': 'Avoid eval(). Use ast.literal_eval() for safe evaluation or json.loads() for JSON'
            },
            'weak_hashing': {
                'regex': r'hashlib\s*\.\s*(md5|sha1)\s*\(',
                'severity': 'MEDIUM',
                'description': 'Weak hashing algorithm (MD5/SHA1) detected',
                'fix': 'Use stronger algorithms like hashlib.sha256() or hashlib.sha512()'
            },
            'sql_injection': {
                'regex': r'(execute\s*\(\s*[fF]["\']|cursor\.execute\s*\(\s*[fF]["\']|["\'].*SELECT.*\{.*["\']|%.*%.*execute)',
                'severity': 'CRITICAL',
                'description': 'Potential SQL injection vulnerability',
                'fix': 'Use parameterized queries with placeholders (e.g., cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)))'
            },
            'missing_input_validation': {
                'regex': r'^[^#]*\binput\s*\(',
                'severity': 'MEDIUM',
                'description': 'Input without validation detected',
                'fix': 'Validate user input with type checking, length limits, and sanitization'
            }
        }
    
    def scan_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Check for f-string SQL queries
                    if re.search(r'[fF]["\'].*SELECT', line, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'file': filepath,
                            'line': line_num,
                            'code': line.strip(),
                            'type': 'sql_injection',
                            'severity': 'CRITICAL',
                            'description': 'Potential SQL injection vulnerability',
                            'fix': 'Use parameterized queries with placeholders (e.g., cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)))'
                        })
                    
                    # Check other patterns
                    for vuln_type, pattern_info in self.patterns.items():
                        if vuln_type == 'sql_injection':
                            continue
                        if re.search(pattern_info['regex'], line, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'file': filepath,
                                'line': line_num,
                                'code': line.strip(),
                                'type': vuln_type,
                                'severity': pattern_info['severity'],
                                'description': pattern_info['description'],
                                'fix': pattern_info['fix']
                            })
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")
    
    def scan_folder(self, folder_path):
        self.vulnerabilities = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)
        return len(self.vulnerabilities)
    
    def generate_report(self, output_file='security_report.txt'):
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SECURE CODING REVIEW REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}\n")
            f.write("=" * 80 + "\n\n")
            
            if not self.vulnerabilities:
                f.write("No vulnerabilities detected. Great job!\n")
            else:
                for idx, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"[{idx}] {vuln['severity']} - {vuln['description']}\n")
                    f.write(f"File: {vuln['file']}\n")
                    f.write(f"Line: {vuln['line']}\n")
                    f.write(f"Code: {vuln['code']}\n")
                    f.write(f"Fix: {vuln['fix']}\n")
                    f.write("-" * 80 + "\n\n")
        
        print(f"\nReport generated: {output_file}")

def main():
    scanner = SecureCodeScanner()
    
    while True:
        print("\n" + "=" * 50)
        print("SECURE CODING REVIEW TOOL")
        print("=" * 50)
        print("1. Scan folder")
        print("2. View report")
        print("3. Exit")
        print("=" * 50)
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == '1':
            folder_path = input("Enter folder path to scan: ").strip()
            if os.path.exists(folder_path):
                print(f"\nScanning {folder_path}...")
                count = scanner.scan_folder(folder_path)
                print(f"Scan complete! Found {count} potential vulnerabilities.")
                scanner.generate_report()
            else:
                print("Invalid folder path!")
        
        elif choice == '2':
            if os.path.exists('security_report.txt'):
                with open('security_report.txt', 'r', encoding='utf-8') as f:
                    print("\n" + f.read())
            else:
                print("No report found. Please scan a folder first.")
        
        elif choice == '3':
            print("Exiting... Stay secure!")
            break
        
        else:
            print("Invalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
