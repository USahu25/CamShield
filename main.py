import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from PIL import Image, ImageTk
import os
import random
import string
import datetime
import cv2
import threading
import smtplib
import ssl
from email.message import EmailMessage
import json
import ctypes
import ctypes.wintypes
import sys

# ---------------- Globals ---------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
camera_enabled = False
cap = None
PREVIEW_SIZE = (320, 240)
PREVIEW_MAX_SIZE = (640, 480)
current_password = "admin123"
EMAIL_CONFIG_FILE = os.path.join(BASE_DIR, "email_config.sec")
PLAIN_EMAIL_CONFIG_FILE = os.path.join(BASE_DIR, "email_config.json")
ATTACH_DIR = os.path.join(BASE_DIR, "snapshots")
os.makedirs(ATTACH_DIR, exist_ok=True)

# ---------------- Helper Functions ---------------- #
def resource_path(filename):
    if os.path.isabs(filename):
        return filename
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = BASE_DIR
    return os.path.join(base_path, filename)

LOG_PATH = os.path.join(BASE_DIR, "activity_log.txt")


def log_action(action):
    with open(LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.datetime.now()}: {action}\n")
    if "refresh_log_view" in globals():
        refresh_log_view()


def read_log_entries():
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as fh:
        lines = [line.rstrip("\n") for line in fh if line.strip()]
    entries = []
    for line in lines:
        try:
            ts, msg = line.split(": ", 1)
            entries.append((ts.strip(), msg.strip()))
        except ValueError:
            entries.append(("", line.strip()))
    return entries


def classify_log_entry(message: str):
    upper = message.upper()
    if "THREAT" in upper or "FAILED" in upper or "BLOCK" in upper or "ATTEMPT" in upper:
        return ("THREAT", "#FF5252", "🛡")
    if "WARNING" in upper or "FAILED" in upper or "ERROR" in upper:
        return ("WARNING", "#FF9800", "⚠")
    if "SUCCESS" in upper or "ENABLED" in upper or "SAVED" in upper or "SENT" in upper:
        return ("SUCCESS", "#00C853", "✔")
    return ("INFO", "#00E5FF", "ℹ")

# ========== Windows DPAPI helpers ========== #
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

def _bytes_to_blob(data: bytes) -> DATA_BLOB:
    blob = DATA_BLOB()
    blob.cbData = len(data)
    blob.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte))
    return blob

def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    size = int(blob.cbData)
    if size == 0:
        return b""
    data = ctypes.string_at(blob.pbData, size)
    kernel32.LocalFree(blob.pbData)
    return data

def dpapi_encrypt(plaintext: bytes) -> bytes:
    in_blob = _bytes_to_blob(plaintext)
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("DPAPI encryption failed")
    return _blob_to_bytes(out_blob)

def dpapi_decrypt(ciphertext: bytes) -> bytes:
    in_blob = _bytes_to_blob(ciphertext)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("DPAPI decryption failed")
    return _blob_to_bytes(out_blob)

# ---------------- Email Config ---------------- #
def save_email_config(cfg: dict):
    try:
        raw = json.dumps(cfg).encode("utf-8")
        enc = dpapi_encrypt(raw)
        with open(EMAIL_CONFIG_FILE, "wb") as f:
            f.write(enc)
        with open(PLAIN_EMAIL_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        log_action("Email config saved.")
    except Exception as e:
        try:
            with open(PLAIN_EMAIL_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            log_action("Email config saved to plain fallback file.")
        except Exception as fallback_error:
            log_action(f"Email config save failed: {e}; fallback error: {fallback_error}")
        messagebox.showerror("Error", f"Failed to save email settings.\n{e}")

def load_email_config() -> dict | None:
    try:
        if os.path.exists(PLAIN_EMAIL_CONFIG_FILE):
            with open(PLAIN_EMAIL_CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            required = {"server", "port", "sender", "password", "recipient", "attach_snapshot"}
            if not required.issubset(set(cfg.keys())):
                return None
            return cfg
        if not os.path.exists(EMAIL_CONFIG_FILE):
            return None
        with open(EMAIL_CONFIG_FILE, "rb") as f:
            enc = f.read()
        raw = dpapi_decrypt(enc)
        cfg = json.loads(raw.decode("utf-8"))
        required = {"server", "port", "sender", "password", "recipient", "attach_snapshot"}
        if not required.issubset(set(cfg.keys())):
            return None
        return cfg
    except Exception as e:
        log_action(f"Email config load failed: {e}")
        return None

# ---------------- Email Alerts ---------------- #
def capture_snapshot() -> str | None:
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(ATTACH_DIR, f"snapshot_{timestamp}.jpg")
        global cap, camera_enabled
        grabbed = False
        frame = None
        if camera_enabled and cap and cap.isOpened():
            ret, f = cap.read()
            if ret:
                grabbed = True
                frame = f
        else:
            backend = getattr(cv2, "CAP_DSHOW", 0)
            temp_cap = cv2.VideoCapture(0, backend)
            if not temp_cap.isOpened() and backend:
                temp_cap = cv2.VideoCapture(0)
            if temp_cap.isOpened():
                ret, f = temp_cap.read()
                temp_cap.release()
                if ret:
                    grabbed = True
                    frame = f
        if grabbed and frame is not None:
            cv2.imwrite(file_path, frame)
            return file_path
    except Exception as e:
        log_action(f"Snapshot failed: {e}")
    return None

def _send_email_smtp(cfg: dict, subject: str, body: str, attach: bool):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg["sender"]
        msg["To"] = cfg["recipient"]
        msg.set_content(body)
        attachment_path = None
        attached_flag = False
        if attach and cfg.get("attach_snapshot", True):
            attachment_path = capture_snapshot()
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as f:
                    data = f.read()
                    msg.add_attachment(data, maintype="image", subtype="jpeg",
                                       filename=os.path.basename(attachment_path))
                attached_flag = True
        context = ssl.create_default_context()
        port = int(cfg["port"])
        if port == 465:
            with smtplib.SMTP_SSL(cfg["server"], port, context=context) as server:
                server.login(cfg["sender"], cfg["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["server"], port, timeout=20) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(cfg["sender"], cfg["password"])
                server.send_message(msg)
        log_action(f"Email sent to {cfg['recipient']}; Subject: {subject}; Snapshot: {attached_flag}")
    except Exception as e:
        log_action(f"Email send failed to {cfg.get('recipient','<unknown>')}; Subject: {subject}; Error: {e}")

def send_email_alert(event_type: str):
    cfg = load_email_config()
    if not cfg:
        log_action("Email alert skipped (not configured).")
        return
    subject = f"[CamShield: Anti-Spyware Webcam Security System] {event_type}"
    body = f"Event: {event_type}\nDate/Time: {datetime.datetime.now()}\n\nAutomated alert."
    t = threading.Thread(target=_send_email_smtp, args=(cfg, subject, body, True), daemon=True)
    t.start()

# ---------------- Camera Control ---------------- #
def disable_camera():
    global cap, camera_enabled
    if cap:
        try:
            cap.release()
        except Exception:
            pass
    camera_enabled = False
    cam_feed_label.config(image='')
    show_placeholder_image()
    log_action("Camera Disabled")
    success_label.config(text="Camera Disabled Successfully!", fg="green")
    send_email_alert("Camera Disabled")

def enable_camera():
    global cap, camera_enabled
    if not camera_enabled:
        try:
            cap = cv2.VideoCapture(0, getattr(cv2, "CAP_DSHOW", 0))
            if not cap.isOpened():
                cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                messagebox.showerror("Error", "Cannot access webcam.\nCheck camera permissions or that the device is connected.")
                show_placeholder_image()
                return
            ret, _ = cap.read()
            if not ret:
                messagebox.showerror("Error", "Webcam is connected but did not return frames.\nTry another camera or reconnect the device.")
                cap.release()
                cap = None
                show_placeholder_image()
                return
        except Exception as e:
            messagebox.showerror("Error", f"Unable to start webcam: {e}")
            show_placeholder_image()
            return
        camera_enabled = True
        log_action("Camera Enabled")
        success_label.config(text="Camera Enabled Successfully!", fg="green")
        update_camera_feed()
        send_email_alert("Camera Enabled")
    else:
        messagebox.showinfo("Info", "Camera already enabled")

def _fit_frame_to_label(frame):
    if frame is None:
        return None
    try:
        width = max(1, cam_feed_label.winfo_width())
        height = max(1, cam_feed_label.winfo_height())
    except Exception:
        width, height = PREVIEW_SIZE
    if width < 1 or height < 1:
        width, height = PREVIEW_SIZE
    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    img = Image.fromarray(frame_rgb)
    img.thumbnail((width, height), Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS)
    return img


def show_placeholder_image():
    if "cam_feed_label" not in globals():
        return
    if os.path.exists(image_path):
        try:
            img = Image.open(image_path)
            img = img.resize(PREVIEW_SIZE, Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS)
            imgtk = ImageTk.PhotoImage(img)
            cam_feed_label.imgtk = imgtk
            cam_feed_label.configure(image=imgtk, text="")
        except Exception:
            cam_feed_label.configure(image='')
    else:
        cam_feed_label.configure(image='')


def update_camera_feed():
    global cap
    if "cam_feed_label" not in globals():
        return
    if camera_enabled and cap and cap.isOpened():
        ret, frame = cap.read()
        if ret and frame is not None:
            try:
                img = _fit_frame_to_label(frame)
                if img is None:
                    raise ValueError("Unable to prepare frame")
                imgtk = ImageTk.PhotoImage(image=img)
                cam_feed_label.imgtk = imgtk
                cam_feed_label.configure(image=imgtk, text="")
            except Exception as e:
                log_action(f"Camera preview failed: {e}")
                show_placeholder_image()
        else:
            show_placeholder_image()
        root.after(100, update_camera_feed)
    else:
        show_placeholder_image()

# ---------------- Password Prompt ---------------- #
def password_prompt(action):
    def verify():
        entered_password = entry.get()
        if entered_password == current_password:
            pw_win.destroy()
            if remember_var.get():
                log_action("User opted to remember password")
            if action == "disable":
                disable_camera()
            elif action == "enable":
                enable_camera()
        else:
            error_label.config(text="Incorrect Password", fg="red")
            entry.delete(0, tk.END)
            log_action("Failed password attempt")
            send_email_alert("Failed Password Attempt")

    def toggle_password():
        entry.config(show="" if show_var.get() else "*")

    pw_win = tk.Toplevel(root)
    pw_win.title("Enter Password")
    pw_win.geometry("300x200")
    pw_win.configure(bg="black")

    tk.Label(pw_win, text="Enter Password:", fg="white", bg="black").pack(pady=5)
    entry = tk.Entry(pw_win, show="*", font=("Arial", 12))
    entry.pack(pady=5)

    show_var = tk.BooleanVar()
    remember_var = tk.BooleanVar()
    tk.Checkbutton(pw_win, text="Show Password", variable=show_var, command=toggle_password, bg="black", fg="white", selectcolor="black").pack(pady=2)
    tk.Checkbutton(pw_win, text="Remember Me", variable=remember_var, bg="black", fg="white", selectcolor="black").pack(pady=2)
    tk.Button(pw_win, text="OK", command=verify, bg="red", fg="white").pack(pady=5)
    error_label = tk.Label(pw_win, text="", fg="red", bg="black")
    error_label.pack()

# ---------------- Change Camera Password ---------------- #
def open_password_tool():
    def save_password(pwd):
        global current_password
        if pwd:
            current_password = pwd
            if "password_footer" in globals() and password_footer.winfo_exists():
                password_footer.config(text=f"Password: {current_password}")
            success_label.config(text="Password Saved Successfully!", fg="green")
        else:
            success_label.config(text="Password cannot be empty.", fg="red")

    def generate_password():
        try:
            length = int(length_entry.get())
            if length < 4:
                raise ValueError
            chars = string.ascii_letters
            if include_numbers.get():
                chars += string.digits
            if include_special.get():
                chars += string.punctuation
            new_pwd = ''.join(random.choices(chars, k=length))
            generated_pwd_var.set(new_pwd)
        except:
            messagebox.showerror("Error", "Enter valid length (>=4)")

    pwd_win = tk.Toplevel(root)
    pwd_win.title("Camera Password Tool")
    pwd_win.geometry("400x300")
    pwd_win.configure(bg="black")

    tk.Label(pwd_win, text="New Password:", fg="white", bg="black").pack(pady=5)
    pwd_entry = tk.Entry(pwd_win, show="*", font=("Arial",12))
    pwd_entry.pack(pady=5)

    tk.Button(pwd_win, text="Save Password", bg="green", fg="white", command=lambda: save_password(pwd_entry.get())).pack(pady=5)

    # Random password generator
    tk.Label(pwd_win, text="Generate Random Password:", fg="white", bg="black").pack(pady=5)
    tk.Label(pwd_win, text="Length:", fg="white", bg="black").pack()
    length_entry = tk.Entry(pwd_win, font=("Arial",12))
    length_entry.insert(0, "8")
    length_entry.pack(pady=5)

    include_numbers = tk.BooleanVar(value=True)
    include_special = tk.BooleanVar(value=False)
    tk.Checkbutton(pwd_win, text="Include Numbers", variable=include_numbers, bg="black", fg="white", selectcolor="black").pack()
    tk.Checkbutton(pwd_win, text="Include Special Characters", variable=include_special, bg="black", fg="white", selectcolor="black").pack()

    generated_pwd_var = tk.StringVar()
    tk.Entry(pwd_win, textvariable=generated_pwd_var, font=("Arial",12)).pack(pady=5)
    tk.Button(pwd_win, text="Generate", bg="orange", fg="white", command=generate_password).pack(pady=5)

# ---------------- Email Settings Window ---------------- #
def open_email_settings():
    def save_cfg():
        try:
            port_value = int(port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Port must be a number.")
            return
        cfg = {
            "server": server_entry.get().strip(),
            "port": port_value,
            "sender": sender_entry.get().strip(),
            "password": pwd_entry.get(),
            "recipient": recipient_entry.get().strip(),
            "attach_snapshot": attach_var.get()
        }
        if not cfg["server"] or not cfg["sender"] or not cfg["recipient"]:
            messagebox.showerror("Error", "Server, sender, and recipient fields are required.")
            return
        if "gmail.com" in cfg["server"].lower() and not cfg["password"]:
            messagebox.showerror("Error", "For Gmail, use an App Password instead of your normal password.")
            return
        save_email_config(cfg)
        messagebox.showinfo("Success", "Email settings saved.\nFor Gmail, use an App Password, not your normal password.")

    def send_test_email():
        cfg = load_email_config()
        if not cfg:
            messagebox.showerror("Error", "Email not configured yet")
            return
        _send_email_smtp(cfg, "Test Email from WebCam Spyware", "This is a test alert.", False)
        messagebox.showinfo("Success", "Test email request sent. Check the log file for the result.")

    email_win = tk.Toplevel(root)
    email_win.title("Email Alert Settings")
    email_win.geometry("400x400")
    email_win.configure(bg="black")

    cfg = load_email_config() or {}

    tk.Label(email_win, text="SMTP Server:", fg="white", bg="black").pack(pady=2)
    server_entry = tk.Entry(email_win, font=("Arial",12))
    server_entry.insert(0, cfg.get("server","smtp.gmail.com"))
    server_entry.pack()

    tk.Label(email_win, text="Port:", fg="white", bg="black").pack(pady=2)
    port_entry = tk.Entry(email_win, font=("Arial",12))
    port_entry.insert(0, cfg.get("port",587))
    port_entry.pack()

    tk.Label(email_win, text="Sender Email:", fg="white", bg="black").pack(pady=2)
    sender_entry = tk.Entry(email_win, font=("Arial",12))
    sender_entry.insert(0, cfg.get("sender",""))
    sender_entry.pack()

    tk.Label(email_win, text="App Password:", fg="white", bg="black").pack(pady=2)
    pwd_entry = tk.Entry(email_win, font=("Arial",12), show="*")
    pwd_entry.insert(0, cfg.get("password",""))
    pwd_entry.pack()

    tk.Label(email_win, text="Recipient Email:", fg="white", bg="black").pack(pady=2)
    recipient_entry = tk.Entry(email_win, font=("Arial",12))
    recipient_entry.insert(0, cfg.get("recipient",""))
    recipient_entry.pack()

    attach_var = tk.BooleanVar(value=cfg.get("attach_snapshot", True))
    tk.Checkbutton(email_win, text="Attach Snapshot", variable=attach_var, bg="black", fg="white", selectcolor="black").pack(pady=5)

    tk.Button(email_win, text="Save Settings", bg="green", fg="white", command=save_cfg).pack(pady=5)
    tk.Button(email_win, text="Send Test Email", bg="blue", fg="white", command=send_test_email).pack(pady=5)

# ---------------- View Logs ---------------- #
def view_logs():
    log_path = os.path.join(BASE_DIR, "activity_log.txt")
    if os.path.exists(log_path):
        os.startfile(log_path)
    else:
        messagebox.showinfo("Logs", "No logs found.")

# ---------------- GUI ---------------- #
def open_project_info():
    project_pdf = resource_path("Project_Info.pdf")
    if os.path.exists(project_pdf):
        os.startfile(project_pdf)
    else:
        messagebox.showinfo("Info", "Project information file not found.")


def copy_demo_password():
    try:
        root.clipboard_clear()
        root.clipboard_append("admin123")
        if "success_label" in globals() and success_label.winfo_exists():
            success_label.config(text="Demo password copied to clipboard.", fg="#00E5FF")
    except Exception as exc:
        messagebox.showerror("Clipboard Error", f"Unable to copy password.\n{exc}")

root = tk.Tk()
root.title("CamShield: Anti-Spyware Webcam Security System")
root.geometry("1400x900")
root.configure(bg="#0B1020")
root.minsize(1120, 780)
root.resizable(True, True)

style = ttk.Style(root)
style.theme_use("clam")
style.configure("Dashboard.TFrame", background="#0B1020")
style.configure("Header.TFrame", background="#0E1630")
style.configure("Card.TFrame", background="#141B2D")
style.configure("Glow.TFrame", background="#141B2D")
style.configure("Status.TLabel", background="#141B2D", foreground="#FFFFFF", font=("Arial", 10))
style.configure("Muted.TLabel", background="#141B2D", foreground="#AAB4C3", font=("Arial", 10))
style.configure("Accent.TLabel", background="#141B2D", foreground="#00E5FF", font=("Arial", 11, "bold"))
style.configure("Title.TLabel", background="#0E1630", foreground="#FFFFFF", font=("Arial", 20, "bold"))
style.configure("Subtitle.TLabel", background="#0E1630", foreground="#AAB4C3", font=("Arial", 11))
style.configure("Small.TLabel", background="#141B2D", foreground="#AAB4C3", font=("Arial", 9))
style.configure("Value.TLabel", background="#141B2D", foreground="#FFFFFF", font=("Arial", 10, "bold"))
style.configure("Success.TLabel", background="#141B2D", foreground="#00C853", font=("Arial", 10, "bold"))
style.configure("Danger.TLabel", background="#141B2D", foreground="#FF3D57", font=("Arial", 10, "bold"))
style.configure("Warning.TLabel", background="#141B2D", foreground="#FF9800", font=("Arial", 10, "bold"))
style.configure("TButton", font=("Arial", 10, "bold"), padding=(12, 8), relief="flat")
style.configure("Primary.TButton", background="#2979FF", foreground="#FFFFFF")
style.configure("Success.TButton", background="#00C853", foreground="#FFFFFF")
style.configure("Danger.TButton", background="#FF3D57", foreground="#FFFFFF")
style.configure("Neutral.TButton", background="#1F2B4A", foreground="#FFFFFF")
style.map("Primary.TButton", background=[("active", "#00E5FF"), ("pressed", "#1B6EFF")], foreground=[("active", "#08111E"), ("pressed", "#FFFFFF")])
style.map("Success.TButton", background=[("active", "#16C96D"), ("pressed", "#009B44")], foreground=[("active", "#FFFFFF"), ("pressed", "#FFFFFF")])
style.map("Danger.TButton", background=[("active", "#FF5D78"), ("pressed", "#D62745")], foreground=[("active", "#FFFFFF"), ("pressed", "#FFFFFF")])
style.map("Neutral.TButton", background=[("active", "#2B3F6B"), ("pressed", "#162546")], foreground=[("active", "#FFFFFF"), ("pressed", "#FFFFFF")])

root.option_add("*Font", "Arial 10")
root.option_add("*Foreground", "#FFFFFF")
root.option_add("*Background", "#0B1020")

canvas = tk.Canvas(root, bg="#0B1020", highlightthickness=0)
canvas.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollbar.pack(side="right", fill="y")
canvas.configure(yscrollcommand=scrollbar.set)

content_frame = ttk.Frame(canvas, style="Dashboard.TFrame")
canvas.create_window((0, 0), window=content_frame, anchor="nw")
content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
content_frame.configure(width=1400, height=1200)

main_container = ttk.Frame(content_frame, style="Card.TFrame")
main_container.place(in_=content_frame, relx=0.5, rely=0.0, anchor="n", y=18)
main_container.columnconfigure(0, weight=1)


def update_dashboard_layout(event=None):
    if not root.winfo_exists():
        return
    usable_width = max(900, min(1280, int(root.winfo_width() * 0.84)))
    main_container.place_configure(relx=0.5, rely=0.0, anchor="n", x=0, y=18, width=usable_width)
    content_frame.update_idletasks()
    canvas.configure(scrollregion=canvas.bbox("all"))

root.bind("<Configure>", update_dashboard_layout)

header = ttk.Frame(main_container, style="Header.TFrame")
header.grid(row=0, column=0, sticky="ew", pady=(0, 16))

logo = tk.Label(header, text="🛡", bg="#0E1630", fg="#00E5FF", font=("Arial", 24, "bold"))
logo.pack(side="left", padx=(12, 10))

header_title = ttk.Label(header, text="CamShield: Anti-Spyware Webcam Security System", style="Title.TLabel")
header_title.pack(side="left", padx=(0, 12))

header_info = ttk.Frame(header, style="Header.TFrame")
header_info.pack(side="right", padx=(0, 10))

time_label = ttk.Label(header_info, text="--:--:--", style="Subtitle.TLabel")
time_label.pack(anchor="e")
status_text = ttk.Label(header_info, text="System Status: Secure", style="Accent.TLabel")
status_text.pack(anchor="e", pady=(2, 0))
connection_label = ttk.Label(header_info, text="● Connected", style="Success.TLabel")
connection_label.pack(anchor="e")

overview_card = ttk.Frame(main_container, style="Glow.TFrame", padding=14)
overview_card.grid(row=1, column=0, sticky="ew", pady=(0, 16))

overview_label = ttk.Label(overview_card, text="System Overview", style="Accent.TLabel")
overview_label.pack(anchor="w", pady=(0, 8))

overview_frame = ttk.Frame(overview_card, style="Card.TFrame")
overview_frame.pack(fill="x")

overview_items = [
    ("Camera Status", "Active"),
    ("Password", "Protected"),
    ("Alerts", "Enabled"),
    ("Monitor", "Running"),
]
for idx, (label_text, value_text) in enumerate(overview_items):
    card = ttk.Frame(overview_frame, style="Glow.TFrame", padding=10)
    card.grid(row=0, column=idx, padx=8, pady=8, sticky="nsew")
    ttk.Label(card, text=label_text, style="Muted.TLabel").pack(anchor="w")
    ttk.Label(card, text=value_text, style="Value.TLabel").pack(anchor="w", pady=(4, 0))

feed_card = ttk.Frame(main_container, style="Glow.TFrame", padding=16)
feed_card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
feed_title = ttk.Label(feed_card, text="Live Webcam Feed", style="Accent.TLabel")
feed_title.pack(anchor="w", pady=(0, 10))

image_path = resource_path("no_camera.jpg")
preview_frame = tk.Frame(feed_card, bg="#10172B", bd=2, relief="ridge")
preview_frame.pack(anchor="center")
preview_frame.configure(width=760, height=320)
preview_frame.pack_propagate(False)
cam_feed_label = tk.Label(preview_frame, bg="#060D1D", bd=2, relief="sunken", fg="#AAB4C3", text="Camera preview will appear here", justify="center", font=("Arial", 10, "bold"))
cam_feed_label.pack(fill="both", expand=True, padx=10, pady=10)
status_badge = tk.Label(feed_card, text="✔ Protected", bg="#141B2D", fg="#00C853", font=("Arial", 11, "bold"))
status_badge.pack(anchor="w", pady=(6, 2))
status_indicator = tk.Label(feed_card, text="●", bg="#141B2D", fg="#00C853", font=("Arial", 18))
status_indicator.pack(anchor="w")

logs_card = ttk.Frame(main_container, style="Glow.TFrame", padding=16)
logs_card.grid(row=3, column=0, sticky="ew", pady=(0, 16))
logs_title_row = ttk.Frame(logs_card, style="Card.TFrame")
logs_title_row.pack(fill="x", pady=(0, 8))
logs_title = ttk.Label(logs_title_row, text="Security Logs", style="Accent.TLabel")
logs_title.pack(side="left", padx=8, pady=6)
logs_count = ttk.Label(logs_title_row, text="Security Logs (0)", style="Subtitle.TLabel")
logs_count.pack(side="right", padx=8, pady=6)

log_tools = ttk.Frame(logs_card, style="Card.TFrame")
log_tools.pack(fill="x", pady=(0, 8))
clear_btn = ttk.Button(log_tools, text="🧹 Clear Logs", command=lambda: clear_logs(), style="Danger.TButton")
clear_btn.pack(side="left", padx=6, pady=6)
export_btn = ttk.Button(log_tools, text="📤 Export Logs", command=lambda: export_logs(), style="Neutral.TButton")
export_btn.pack(side="left", padx=6, pady=6)

log_frame = ttk.Frame(logs_card, style="Card.TFrame")
log_frame.pack(fill="x", pady=(4, 0))
log_text = tk.Text(log_frame, height=8, bg="#0F1426", fg="#DDEBFF", insertbackground="#FFFFFF", relief="flat", font=("Consolas", 9))
log_text.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=4)
log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_scroll.pack(side="right", fill="y", pady=4)
log_text.configure(yscrollcommand=log_scroll.set)
log_text.tag_configure("info", foreground="#00E5FF")
log_text.tag_configure("success", foreground="#00C853")
log_text.tag_configure("warning", foreground="#FF9800")
log_text.tag_configure("threat", foreground="#FF5252")

log_text_widget = log_text
log_count_label = logs_count


def refresh_log_view():
    entries = read_log_entries()
    log_text_widget.configure(state="normal")
    log_text_widget.delete("1.0", "end")
    if not entries:
        log_text_widget.insert("end", "No log activity yet.\n", "info")
    else:
        for ts, message in entries:
            category, color, icon = classify_log_entry(message)
            tag = category.lower()
            prefix = f"{icon} {ts} " if ts else f"{icon} "
            display = f"{prefix}{message}\n"
            log_text_widget.insert("end", display, tag)
    log_text_widget.configure(state="disabled")
    log_count_label.configure(text=f"Security Logs ({len(entries)})")
    log_text_widget.see("end")


def clear_logs():
    with open(LOG_PATH, "w", encoding="utf-8") as fh:
        fh.write("")
    refresh_log_view()


def export_logs():
    entries = read_log_entries()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    export_path = os.path.join(BASE_DIR, f"security_logs_{timestamp}.txt")
    with open(export_path, "w", encoding="utf-8") as fh:
        for ts, message in entries:
            fh.write(f"{ts}: {message}\n")
    messagebox.showinfo("Exported", f"Logs exported to:\n{export_path}")

refresh_log_view()

actions_card = ttk.Frame(main_container, style="Glow.TFrame", padding=16)
actions_card.grid(row=4, column=0, sticky="ew", pady=(0, 16))
quick_title = ttk.Label(actions_card, text="Quick Actions", style="Accent.TLabel")
quick_title.pack(anchor="w", pady=(0, 10))
action_frame = ttk.Frame(actions_card, style="Card.TFrame")
action_frame.pack(fill="x")
button_defs = [
    ("🟢 Enable Camera", lambda: password_prompt("enable"), "Success.TButton"),
    ("🔴 Disable Camera", lambda: password_prompt("disable"), "Danger.TButton"),
    ("📧 Email Alerts", open_email_settings, "Primary.TButton"),
    ("📋 View Logs", view_logs, "Neutral.TButton"),
    ("🔐 Change Camera Password", open_password_tool, "Neutral.TButton"),
    ("ℹ Project Info", open_project_info, "Neutral.TButton"),
]
for idx, (text, command, style_name) in enumerate(button_defs):
    button = ttk.Button(action_frame, text=text, command=command, style=style_name)
    button.grid(row=idx // 3, column=idx % 3, padx=8, pady=8, sticky="nsew")
    action_frame.columnconfigure(0, weight=1)
    action_frame.columnconfigure(1, weight=0)
    action_frame.columnconfigure(2, weight=1)

exit_btn = ttk.Button(actions_card, text="🚪 Exit", command=root.destroy, style="Danger.TButton")
exit_btn.pack(anchor="e", pady=(10, 0))

demo_card = tk.Frame(actions_card, bg="#10172B", bd=2, relief="ridge", highlightbackground="#00E5FF", highlightthickness=2, padx=14, pady=12)
demo_card.pack(fill="x", pady=(12, 0), padx=6)

demo_header = tk.Frame(demo_card, bg="#10172B")
demo_header.pack(anchor="center", pady=(0, 6))

demo_icon = tk.Label(demo_header, text="🔑", bg="#10172B", fg="#00E5FF", font=("Arial", 13, "bold"))
demo_icon.pack(side="left", padx=(0, 6))
demo_title = tk.Label(demo_header, text="Demo Credentials", bg="#10172B", fg="#00E5FF", font=("Arial", 12, "bold"))
demo_title.pack(side="left")

demo_pw_frame = tk.Frame(demo_card, bg="#10172B")
demo_pw_frame.pack(anchor="center", pady=(2, 4))

demo_label = tk.Label(demo_pw_frame, text="Default Camera Password", bg="#10172B", fg="#AAB4C3", font=("Arial", 10))
demo_label.pack(anchor="w", padx=6, pady=(0, 4))

demo_entry = tk.Entry(demo_pw_frame, width=22, font=("Arial", 13, "bold"), fg="#00E5FF", bg="#060D1D", insertbackground="#FFFFFF", relief="solid", bd=1, justify="center")
demo_entry.insert(0, "admin123")
demo_entry.configure(state="readonly")
demo_entry.pack(side="left", padx=(6, 8), pady=(2, 0))

copy_demo_btn = tk.Button(demo_pw_frame, text="Copy", command=copy_demo_password, bg="#2979FF", fg="#FFFFFF", font=("Arial", 10, "bold"))
copy_demo_btn.pack(side="left", pady=(2, 0))

demo_note = tk.Label(demo_card, text="Use this password whenever camera authentication is requested.", bg="#10172B", fg="#AAB4C3", font=("Arial", 10))
demo_note.pack(anchor="center", pady=(6, 0))

bottom_bar = ttk.Frame(main_container, style="Header.TFrame")
bottom_bar.grid(row=5, column=0, sticky="ew", pady=(0, 10))
status_label = ttk.Label(bottom_bar, text="Monitoring Active", style="Accent.TLabel")
status_label.pack(side="left", padx=12, pady=8)

cpu_var = tk.DoubleVar(value=40)
memory_var = tk.DoubleVar(value=55)
cpu_bar = ttk.Progressbar(bottom_bar, orient="horizontal", mode="determinate", variable=cpu_var, maximum=100)
cpu_bar.pack(side="left", padx=(8, 4), pady=8)
mem_bar = ttk.Progressbar(bottom_bar, orient="horizontal", mode="determinate", variable=memory_var, maximum=100)
mem_bar.pack(side="left", padx=(4, 8), pady=8)
info_bar = ttk.Label(bottom_bar, text="CPU 45%   Memory 55%   User: admin   Version 1.0", style="Subtitle.TLabel")
info_bar.pack(side="right", padx=12, pady=8)

password_footer = tk.Label(bottom_bar, text=f"Password: {current_password}", fg="#00E5FF", bg="#0E1630", font=("Arial", 10, "bold"))
password_footer.pack(side="left", padx=(12, 0), pady=8)

success_label = tk.Label(main_container, text="", fg="#00C853", bg="#141B2D", font=("Arial", 10, "bold"))
success_label.grid(row=6, column=0, pady=(4, 8))

root.update_idletasks()
update_dashboard_layout()
content_frame.update_idletasks()
canvas.configure(scrollregion=canvas.bbox("all"))


def update_clock():
    if "time_label" in globals():
        time_label.configure(text=datetime.datetime.now().strftime("%H:%M:%S"))
    root.after(1000, update_clock)


def pulse_status():
    if "status_indicator" in globals() and "status_badge" in globals():
        if camera_enabled:
            status_indicator.configure(fg="#00C853" if status_indicator.cget("fg") == "#FF9800" else "#FF9800")
            status_badge.configure(fg="#00C853" if status_badge.cget("fg") == "#FF9800" else "#FF9800")
            status_badge.configure(text="⚠ Camera In Use")
        else:
            status_indicator.configure(fg="#00C853")
            status_badge.configure(fg="#00C853")
            status_badge.configure(text="✔ Protected")
    root.after(700, pulse_status)


def animate_bars():
    if "cpu_var" in globals() and "memory_var" in globals():
        cpu_var.set((cpu_var.get() + 8) % 100)
        memory_var.set((memory_var.get() + 6) % 100)
        info_bar.configure(text=f"CPU {int(cpu_var.get())}%   Memory {int(memory_var.get())}%   User: admin   Version 1.0")
    root.after(1200, animate_bars)

update_clock()
pulse_status()
animate_bars()

root.mainloop()
