# 6caner - PHP Malware Scanner

**6caner** is a lightweight PHP malware scanner that detects suspicious functions like `eval(base64_decode())`, `shell_exec()`, and other potentially dangerous PHP code.

## 🚀 Features
- Recursively scans all PHP files in a directory
- Detects known malicious patterns such as:
  - `eval(base64_decode(...))`
  - `system()`, `shell_exec()`, `assert()`, etc.
- Logs suspicious files into `infected.log`
- Optional email alert support

## ⚙️ Usage

From the command line:

```bash
php 6caner.php /path/to/scan
```

If no path is specified, it scans the current working directory.

## 📥 Output

If suspicious code is detected:
- It is logged to `infected.log`
- If configured, an email alert will be sent to the address specified in `SEND_EMAIL_ALERTS_TO`

## 🛡️ Example Suspicious Patterns Detected

- `eval(base64_decode(...))`
- `assert(...)`
- `preg_replace(..., /e)`
- `shell_exec(...)`
- and more...

## 🧑‍💻 Author
Coded and enhanced by [0x6ick](https://github.com/6ickzone)  
Based on open mod by **Michael Stowe**

## 🪪 License
This project is licensed under the GPL-2.0 License.
