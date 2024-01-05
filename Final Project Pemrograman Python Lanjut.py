import tkinter as tk
from tkinter import filedialog
import requests
import hashlib
import os

class Antivirus:
    def __init__(self, api_key):
        self.api_key = api_key

    def scan_file(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.api_key}
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            files = {'file': (file_path, file_data)}
            response = requests.post(url, files=files, params=params)
            
        if response.status_code == 200:
            result_data = response.json()
            return f"\nFile: {file_path}\nStatus: File is being scanned\nSHA256: {result_data['sha256']}\nLink: {result_data['permalink']}\n"
        elif response.status_code == 204:
            return f"File: {file_path}\nStatus: File already scanned\n"
        else:
            return f"File: {file_path}\nError: {response.status_code}\n"
        
    def get_scan_results(self, file_hash):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.api_key, 'resource': file_hash}
        response = requests.get(url, params=params)

        if response.status_code == 200:
            result_data = response.json()
            if result_data['positives'] > 0:
                result = f"Result: {file_hash} is MALWARE detected by {result_data['positives']} / {result_data['total']} antivirus engines\n"
            else:
                result = f"Result: {file_hash} is NOT malware\n"
            return result
        elif response.status_code == 204:
            return f"Result: No scan results found for file hash: {file_hash}\n"
        else:
            return f"Error: Unable to fetch scan results for file hash: {file_hash}\n"

class Application(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("Antivirus")

        self.frame = tk.Frame(self)
        self.frame.pack(padx=10, pady=10)
        
        self.browse_button = tk.Button(self.frame, text="Browse Folder", command=self.browse_folder)
        self.browse_button.pack()
        self.label = tk.Label(self.frame, text="")
        self.label.pack()

        self.scan_button = tk.Button(self.frame, text="Scan Files", command=self.scan_files)
        self.scan_button.pack()

        self.output_text = tk.Text(self, wrap=tk.WORD)
        self.output_text.pack(padx=20, pady=20)

    def browse_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_path = folder_path
            self.label.config(text=self.folder_path)

    def scan_files(self):
        api_key = '86d71e7f9c02237bbc04cfde9a2d82cfba7e67ef670c3ede6851ed9e8dbe3d20'
        folder_path = self.folder_path
        antivirus = Antivirus(api_key)
        
        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(file_path):
                result = antivirus.scan_file(file_path)
                self.output_text.insert(tk.END, result)
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    file_hash = hashlib.sha256(file_data).hexdigest()
                response = antivirus.get_scan_results(file_hash)
                self.output_text.insert(tk.END, response)

app = Application()
app.mainloop()
