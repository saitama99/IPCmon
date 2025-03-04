#https://github.com/saitama99
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage
import frida
import psutil
import json
from datetime import datetime

class IPCMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Pipe Monitor")
        self.root.geometry("800x600")
        
        # Set application icon
        self.set_icon()

        self.setup_gui()
        self.captured_data = []
        self.monitoring = False
        
    def set_icon(self):
        try:
            self.root.iconbitmap('icon.ico')  
        except tk.TclError:
            try:
                self.icon_img = PhotoImage(file="icon.png")
                self.root.tk.call('wm', 'iconphoto', self.root._w, self.icon_img)
            except Exception as e:
                print("Error setting icon:", e)

    def setup_gui(self):
        frame = ttk.Frame(self.root, padding="5")
        frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(frame, text="Enter PID or Process Name:").pack(side=tk.LEFT)
        self.input_entry = ttk.Entry(frame, width=20)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(frame, text="List Processes", command=self.show_processes).pack(side=tk.LEFT, padx=5)
        self.monitor_btn = ttk.Button(frame, text="Start Monitor", command=self.toggle_monitoring)
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(frame, text="Clear Screen", command=self.clear_screen)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Log area with scrollbar
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(log_frame, height=20, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(self.root, text="Export Data", command=self.export_data).pack(pady=5)

    def show_processes(self):
        win = tk.Toplevel(self.root)
        win.title("Running Processes")
        win.geometry("400x300")
        
        tree = ttk.Treeview(win, columns=("PID", "Name"), show="headings")
        tree.heading("PID", text="PID")
        tree.heading("Name", text="Process Name")
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                tree.insert("", tk.END, values=(proc.info['pid'], proc.info['name']))
            except:
                continue
                
        def on_select(event):
            selected = tree.selection()
            if selected:
                item = tree.item(selected[0])
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, item['values'][0])  
                win.destroy()
                
        tree.bind('<<TreeviewSelect>>', on_select)
        tree.pack(fill=tk.BOTH, expand=True)

    def on_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            self.captured_data.append(payload)
            log_message = f"[{payload['timestamp']}] {payload['type']}: {payload['data_size']} bytes\n"
            
            if payload.get("data"):
                try:
                    decoded_data = bytes.fromhex(payload['data']).decode('utf-8', 'ignore')
                    log_message += f"Data: {decoded_data}\n"
                except Exception:
                    log_message += f"Data (hex): {payload['data']}\n"
        
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)

    def toggle_monitoring(self):
        if not self.monitoring:
            target = self.input_entry.get().strip()
            try:
                if target.isdigit():
                    pid = int(target)
                    if not psutil.pid_exists(pid):
                        raise ValueError(f"PID {pid} does not exist")
                    process = frida.attach(pid)
                else:
                    process = frida.attach(target)

                script_code = """
                var createFile = Module.getExportByName('kernel32.dll', 'CreateFileW');
                var readFile = Module.getExportByName('kernel32.dll', 'ReadFile');
                var writeFile = Module.getExportByName('kernel32.dll', 'WriteFile');

                function arrayBufferToHex(buffer) {
                    var hexString = '';
                    var byteArray = new Uint8Array(buffer);
                    for (var i = 0; i < byteArray.length; i++) {
                        hexString += byteArray[i].toString(16).padStart(2, '0');
                    }
                    return hexString;
                }

                Interceptor.attach(createFile, {
                    onEnter: function(args) {
                        send({
                            type: 'create_file',
                            timestamp: new Date().toISOString(),
                            data: args[0].readUtf16String()
                        });
                    }
                });

                Interceptor.attach(readFile, {
                    onEnter: function(args) {
                        var bytesRead = args[2].toInt32();
                        var buffer = args[1];
                        var data = buffer.readByteArray(bytesRead);
                        send({
                            type: 'read_file',
                            timestamp: new Date().toISOString(),
                            data_size: bytesRead,
                            data: arrayBufferToHex(data)
                        });
                    }
                });

                Interceptor.attach(writeFile, {
                    onEnter: function(args) {
                        var bytesWritten = args[2].toInt32();
                        var buffer = args[1];
                        var data = buffer.readByteArray(bytesWritten);
                        send({
                            type: 'write_file',
                            timestamp: new Date().toISOString(),
                            data_size: bytesWritten,
                            data: arrayBufferToHex(data)
                        });
                    }
                });
                """
                
                self.script = process.create_script(script_code)
                self.script.on('message', self.on_message)
                self.script.load()
                
                self.monitoring = True
                self.monitor_btn.configure(text="Stop Monitor")
                self.input_entry.configure(state="disabled")
                self.log_text.insert(tk.END, f"Started monitoring {target}\n")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to attach: {str(e)}")
                
        else:
            try:
                if hasattr(self, 'script'):
                    self.script.unload()
                self.monitoring = False
                self.monitor_btn.configure(text="Start Monitor")
                self.input_entry.configure(state="normal")
                self.log_text.insert(tk.END, "Stopped monitoring\n")
            except Exception as e:
                messagebox.showerror("Error", f"Error stopping: {str(e)}")

    def export_data(self):
        if not self.captured_data:
            messagebox.showinfo("Info", "No data to export")
            return
        
        decoded_data = []
        for entry in self.captured_data:
            if 'data' in entry:
                try:
                    decoded_entry = entry.copy()
                    decoded_entry['data'] = bytes.fromhex(entry['data']).decode('utf-8', 'ignore')
                    decoded_data.append(decoded_entry)
                except Exception:
                    decoded_data.append(entry)
            else:
                decoded_data.append(entry)

        filename = f"pipe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(decoded_data, f, indent=2)
        messagebox.showinfo("Success", f"Data exported to {filename}")
        
    def clear_screen(self):
        self.log_text.delete(1.0, tk.END)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    monitor = IPCMonitor()
    monitor.run()
