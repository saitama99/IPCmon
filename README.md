# IPCmon - Inter-Process Communication Monitor

**IPCmon** is a Python-based tool that allows you to monitor and sniff data in **Inter-Process Communication (IPC)** mechanisms like **Named Pipes** on Windows. It utilizes **Frida** to hook into processes and capture IPC communication.

## 🚀 Features
- 🔍 Monitor **Named Pipe communication** in Windows applications.
- 📡 Capture **data sent and received** through pipes.
- 📂 Export captured data in **JSON format**.
- 🖥 GUI-based **process selection and monitoring**.
- 🔠 **Hex and ASCII representation** of captured data.

---

## 🛠 Requirements

Before running **IPCmon**, ensure you have the following installed:

### 1️⃣ Install Python  
Make sure you have **Python 3.8+** installed. You can download it from [python.org](https://www.python.org/downloads/).

### 2️⃣ Install Dependencies  
Run the following command to install the required packages:

```sh
pip install -r requirements.txt
