import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Secure Code Scanner")
        self.root.geometry("1000x750")
        self.root.configure(bg='#1e1e1e')
        
        self.vulnerabilities = []
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title = tk.Label(self.root, text="🔒 SECURE CODE SCANNER", 
                        font=("Arial", 26, "bold"), bg='#1e1e1e', fg='#00ff00')
        title.pack(pady=20)
        
        # Folder frame
        folder_frame = tk.Frame(self.root, bg='#2d2d2d', relief='raised', bd=2)
        folder_frame.pack(pady=10, padx=20, fill='x')
        
        self.path_label = tk.Label(folder_frame, text="📁 No folder selected", 
                                   font=("Arial", 11), bg='#2d2d2d', fg='#ffffff', anchor='w')
        self.path_label.pack(side='left', padx=15, pady=15, fill='x', expand=True)
        
        browse_btn = tk.Button(folder_frame, text="BROWSE", command=self.select_folder,
                              font=("Arial", 11, "bold"), bg='#0078d4', fg='white', 
                              padx=30, pady=10, cursor='hand2')
        browse_btn.pack(side='right', padx=10, pady=10)
        
        # Scan button
        self.scan_btn = tk.Button(self.root, text="🔍 START SCAN", command=self.scan,
                                 font=("Arial", 16, "bold"), bg='#dc3545', fg='white',
                                 padx=50, pady=20, cursor='hand2')
        self.scan_btn.pack(pady=15)
        
        # Status label
        self.status_label = tk.Label(self.root, text="Ready to scan", 
                                     font=("Arial", 10), bg='#1e1e1e', fg='#00ff00')
        self.status_label.pack()
        
        # Results
        result_frame = tk.Frame(self.root, bg='#1e1e1e')
        result_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        tk.Label(result_frame, text="📊 SCAN RESULTS:", font=("Arial", 13, "bold"),
                bg='#1e1e1e', fg='#ffffff').pack(anchor='w', pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, font=("Consolas", 10),
                                                     bg='#0d1117', fg='#c9d1d9', 
                                                     insertbackground='white', wrap=tk.WORD)
        self.result_text.pack(fill='both', expand=True)
        
        # Buttons
        btn_frame = tk.Frame(self.root, bg='#1e1e1e')
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="💾 SAVE REPORT", command=self.save_report,
                 font=("Arial", 11, "bold"), bg='#28a745', fg='white', 
                 padx=25, pady=12, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="🗑️ CLEAR", command=self.clear,
                 font=("Arial", 11, "bold"), bg='#6c757d', fg='white',
                 padx=25, pady=12, cursor='hand2').pack(side='left', padx=5)
    
    def select_folder(self):
        folder = filedialog.askdirectory(title="Select Python Project Folder")
        if folder:
            self.folder_path = folder
            self.path_label.config(text=f"📁 {folder}")
    
    def scan(self):
        if not hasattr(self, 'folder_path'):
            messagebox.showwarning("Warning", "Please select a folder first!")
            return
        
        self.vulnerabilities = []
        self.result_text.delete(1.0, tk.END)
        self.status_label.config(text="⏳ Scanning...", fg='#ffc107')
        self.root.update()
        
        file_count = 0
        for root, dirs, files in os.walk(self.folder_path):
            for file in files:
                if file.endswith('.py'):
                    file_count += 1
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)
        
        self.display_results(file_count)
        self.status_label.config(text="✅ Scan completed!", fg='#00ff00')
    
    def scan_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    line_lower = line.lower()
                    
                    # 1. Hardcoded secrets
                    if re.search(r'(password|passwd|pwd|secret|api_key|token|key)\s*=\s*["\'][^"\']{3,}["\']', line, re.IGNORECASE):
                        self.add_vuln(filepath, line_num, line, 'CRITICAL', 
                                     'Hardcoded Secret/Password',
                                     'Use environment variables: os.getenv("SECRET_KEY")')
                    
                    # 2. eval() usage
                    if re.search(r'\beval\s*\(', line):
                        self.add_vuln(filepath, line_num, line, 'CRITICAL',
                                     'Dangerous eval() function',
                                     'Use ast.literal_eval() or json.loads()')
                    
                    # 3. Weak hashing
                    if re.search(r'hashlib\s*\.\s*(md5|sha1)\s*\(', line, re.IGNORECASE):
                        self.add_vuln(filepath, line_num, line, 'HIGH',
                                     'Weak Hashing Algorithm (MD5/SHA1)',
                                     'Use hashlib.sha256() or hashlib.sha512()')
                    
                    # 4. SQL Injection - f-string
                    if re.search(r'[fF]["\'].*SELECT.*["\']', line, re.IGNORECASE):
                        self.add_vuln(filepath, line_num, line, 'CRITICAL',
                                     'SQL Injection Risk (f-string)',
                                     'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (id,))')
                    
                    # 5. SQL Injection - string format
                    if 'execute' in line_lower and ('%s' in line or '.format' in line_lower):
                        self.add_vuln(filepath, line_num, line, 'CRITICAL',
                                     'SQL Injection Risk (string formatting)',
                                     'Use parameterized queries with placeholders')
                    
                    # 6. Missing input validation
                    if re.search(r'^\s*\w+\s*=\s*input\s*\(', line):
                        self.add_vuln(filepath, line_num, line, 'MEDIUM',
                                     'Missing Input Validation',
                                     'Validate input: int(input()) or add try-except with validation')
        except Exception as e:
            pass
    
    def add_vuln(self, filepath, line_num, code, severity, desc, fix):
        self.vulnerabilities.append({
            'file': filepath,
            'line': line_num,
            'code': code.strip(),
            'severity': severity,
            'description': desc,
            'fix': fix
        })
    
    def display_results(self, file_count):
        self.result_text.delete(1.0, tk.END)
        
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        header = f"{'='*90}\n"
        header += f"  SECURITY SCAN REPORT\n"
        header += f"{'='*90}\n"
        header += f"  📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"  📁 Folder: {self.folder_path}\n"
        header += f"  📄 Python Files Scanned: {file_count}\n"
        header += f"  ⚠️  Vulnerabilities Found: {len(self.vulnerabilities)}\n"
        header += f"{'='*90}\n\n"
        
        self.result_text.insert(tk.END, header)
        
        if not self.vulnerabilities:
            self.result_text.insert(tk.END, "✅ EXCELLENT! No vulnerabilities detected.\n\n")
            self.result_text.insert(tk.END, "Your code follows secure coding practices!")
        else:
            # Group by severity
            critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
            high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
            medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
            
            summary = f"SUMMARY:\n"
            summary += f"  🔴 Critical: {len(critical)}\n"
            summary += f"  🟠 High: {len(high)}\n"
            summary += f"  🟡 Medium: {len(medium)}\n\n"
            summary += f"{'-'*90}\n\n"
            
            self.result_text.insert(tk.END, summary)
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                icon = icons.get(vuln['severity'], '⚪')
                
                output = f"[{idx}] {icon} {vuln['severity']} - {vuln['description']}\n"
                output += f"     📄 File: {vuln['file']}\n"
                output += f"     📍 Line: {vuln['line']}\n"
                output += f"     💻 Code: {vuln['code'][:80]}{'...' if len(vuln['code']) > 80 else ''}\n"
                output += f"     ✅ Fix: {vuln['fix']}\n"
                output += f"{'-'*90}\n\n"
                
                self.result_text.insert(tk.END, output)
        
        if self.vulnerabilities:
            messagebox.showwarning("Vulnerabilities Found!", 
                                  f"⚠️ Found {len(self.vulnerabilities)} security issues!\n\nPlease review and fix them.")
        else:
            messagebox.showinfo("Scan Complete", "✅ No vulnerabilities found!\n\nGreat job!")
    
    def save_report(self):
        if not self.vulnerabilities and not hasattr(self, 'folder_path'):
            messagebox.showwarning("Warning", "No scan results to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.result_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"✅ Report saved!\n\n{filename}")
    
    def clear(self):
        self.result_text.delete(1.0, tk.END)
        self.vulnerabilities = []
        if hasattr(self, 'folder_path'):
            delattr(self, 'folder_path')
        self.path_label.config(text="📁 No folder selected")
        self.status_label.config(text="Ready to scan", fg='#00ff00')

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    root.mainloop()
