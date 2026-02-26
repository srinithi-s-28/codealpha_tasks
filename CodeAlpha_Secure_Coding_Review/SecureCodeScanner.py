import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from datetime import datetime

class SecureCodeScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Code Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        self.vulnerabilities = []
        self.patterns = {
            'hardcoded_password': {
                'regex': r'(password|passwd|pwd|pass|secret|key|token)\s*=\s*["\'][^"\']{3,}["\']',
                'severity': 'HIGH',
                'description': 'Hardcoded password detected',
                'fix': 'Use environment variables: os.getenv("PASSWORD")'
            },
            'eval_usage': {
                'regex': r'\beval\s*\(',
                'severity': 'CRITICAL',
                'description': 'Use of eval() function',
                'fix': 'Use ast.literal_eval() or json.loads() instead'
            },
            'weak_hashing': {
                'regex': r'hashlib\s*\.\s*(md5|sha1)\s*\(',
                'severity': 'MEDIUM',
                'description': 'Weak hashing (MD5/SHA1)',
                'fix': 'Use hashlib.sha256() or hashlib.sha512()'
            },
            'sql_injection': {
                'regex': r'(cursor\.execute\s*\(\s*[fF]["\'\s]|execute\s*\(\s*[fF]["\'\s]|[fF]["\'\s].*SELECT.*\{)',
                'severity': 'CRITICAL',
                'description': 'SQL injection risk',
                'fix': 'Use parameterized queries with placeholders'
            },
            'missing_input_validation': {
                'regex': r'^[^#]*\binput\s*\(',
                'severity': 'MEDIUM',
                'description': 'Missing input validation',
                'fix': 'Validate with type checking and sanitization'
            }
        }
        
        self.create_widgets()
    
    def create_widgets(self):
        # Header
        header = tk.Label(self.root, text="🔒 SECURE CODE SCANNER", 
                         font=("Arial", 24, "bold"), bg='#2c3e50', fg='#ecf0f1')
        header.pack(pady=20)
        
        # Folder selection frame
        folder_frame = tk.Frame(self.root, bg='#34495e')
        folder_frame.pack(pady=10, padx=20, fill='x')
        
        self.folder_label = tk.Label(folder_frame, text="No folder selected", 
                                     font=("Arial", 10), bg='#34495e', fg='#ecf0f1')
        self.folder_label.pack(side='left', padx=10)
        
        browse_btn = tk.Button(folder_frame, text="📁 Browse Folder", 
                              command=self.browse_folder, font=("Arial", 11, "bold"),
                              bg='#3498db', fg='white', padx=20, pady=10)
        browse_btn.pack(side='right', padx=10, pady=10)
        
        # Scan button
        scan_btn = tk.Button(self.root, text="🔍 SCAN NOW", 
                            command=self.scan_folder, font=("Arial", 14, "bold"),
                            bg='#e74c3c', fg='white', padx=40, pady=15)
        scan_btn.pack(pady=10)
        
        # Results frame
        results_frame = tk.Frame(self.root, bg='#2c3e50')
        results_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        tk.Label(results_frame, text="Scan Results:", font=("Arial", 12, "bold"),
                bg='#2c3e50', fg='#ecf0f1').pack(anchor='w')
        
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                      font=("Consolas", 10),
                                                      bg='#ecf0f1', fg='#2c3e50',
                                                      wrap=tk.WORD)
        self.results_text.pack(fill='both', expand=True, pady=5)
        
        # Buttons frame
        btn_frame = tk.Frame(self.root, bg='#2c3e50')
        btn_frame.pack(pady=10)
        
        save_btn = tk.Button(btn_frame, text="💾 Save Report", 
                            command=self.save_report, font=("Arial", 11),
                            bg='#27ae60', fg='white', padx=20, pady=10)
        save_btn.pack(side='left', padx=5)
        
        clear_btn = tk.Button(btn_frame, text="🗑️ Clear", 
                             command=self.clear_results, font=("Arial", 11),
                             bg='#95a5a6', fg='white', padx=20, pady=10)
        clear_btn.pack(side='left', padx=5)
    
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Project Folder")
        if folder:
            self.selected_folder = folder
            self.folder_label.config(text=f"Selected: {folder}")
    
    def scan_folder(self):
        if not hasattr(self, 'selected_folder'):
            messagebox.showwarning("Warning", "Please select a folder first!")
            return
        
        self.vulnerabilities = []
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scanning...\n\n")
        self.root.update()
        
        py_files = 0
        for root, dirs, files in os.walk(self.selected_folder):
            for file in files:
                if file.endswith('.py'):
                    py_files += 1
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)
        
        self.display_results(py_files)
    
    def scan_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Check for f-string SQL queries (multi-line support)
                    if re.search(r'[fF]["\'].*SELECT', line, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'file': filepath,
                            'line': line_num,
                            'code': line.strip(),
                            'severity': 'CRITICAL',
                            'description': 'SQL injection risk',
                            'fix': 'Use parameterized queries with placeholders'
                        })
                    
                    # Check other patterns
                    for vuln_type, pattern_info in self.patterns.items():
                        if vuln_type == 'sql_injection':
                            continue  # Already handled above
                        if re.search(pattern_info['regex'], line, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'file': filepath,
                                'line': line_num,
                                'code': line.strip(),
                                'severity': pattern_info['severity'],
                                'description': pattern_info['description'],
                                'fix': pattern_info['fix']
                            })
        except:
            pass
    
    def display_results(self, py_files):
        self.results_text.delete(1.0, tk.END)
        
        header = f"{'='*80}\n"
        header += f"SCAN COMPLETED\n"
        header += f"{'='*80}\n"
        header += f"Files Scanned: {py_files}\n"
        header += f"Vulnerabilities Found: {len(self.vulnerabilities)}\n"
        header += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"{'='*80}\n\n"
        
        self.results_text.insert(tk.END, header)
        
        if not self.vulnerabilities:
            self.results_text.insert(tk.END, "✅ No vulnerabilities detected! Great job!\n")
        else:
            severity_colors = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡'}
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                icon = severity_colors.get(vuln['severity'], '⚪')
                result = f"[{idx}] {icon} {vuln['severity']} - {vuln['description']}\n"
                result += f"📄 File: {vuln['file']}\n"
                result += f"📍 Line: {vuln['line']}\n"
                result += f"💻 Code: {vuln['code']}\n"
                result += f"✅ Fix: {vuln['fix']}\n"
                result += f"{'-'*80}\n\n"
                
                self.results_text.insert(tk.END, result)
        
        if self.vulnerabilities:
            messagebox.showinfo("Scan Complete", 
                              f"Found {len(self.vulnerabilities)} vulnerabilities!")
        else:
            messagebox.showinfo("Scan Complete", "No vulnerabilities found!")
    
    def save_report(self):
        if not self.vulnerabilities and not hasattr(self, 'selected_folder'):
            messagebox.showwarning("Warning", "No scan results to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.results_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"Report saved to:\n{filename}")
    
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.vulnerabilities = []
        if hasattr(self, 'selected_folder'):
            delattr(self, 'selected_folder')
        self.folder_label.config(text="No folder selected")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureCodeScannerGUI(root)
    root.mainloop()
