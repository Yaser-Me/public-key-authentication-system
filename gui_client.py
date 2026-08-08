import tkinter as tk
from tkinter import messagebox

from client import register_device, login


def do_register():
    user_id = entry_user.get().strip()
    device_id = entry_device.get().strip()
    authorization_id = entry_authorization_id.get().strip()
    authorization_secret = entry_authorization_secret.get().strip()

    if not user_id or not device_id or not authorization_id or not authorization_secret:
        messagebox.showerror(
            "Error",
            "Enter user ID, device ID, authorization ID, and authorization secret.",
        )
        return

    try:
        resp = register_device(
            user_id,
            device_id,
            authorization_id,
            authorization_secret,
        )
        messagebox.showinfo("Register", str(resp))
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed:\n{e}")


def do_login():
    user_id = entry_user.get().strip()
    device_id = entry_device.get().strip()

    if not user_id or not device_id:
        messagebox.showerror("Error", "Please enter both user ID and device ID.")
        return

    try:
        resp = login(user_id, device_id)  # private key is loaded from disk inside client.py
        messagebox.showinfo("Login", str(resp))
    except Exception as e:
        messagebox.showerror("Error", f"Login failed:\n{e}")


#----- GUI layout ----

root = tk.Tk()
root.title("Passwordless Auth Demo")

tk.Label(root, text="User ID").pack(pady=(10, 0))
entry_user = tk.Entry(root, width=30)
entry_user.pack()

tk.Label(root, text="Device ID").pack(pady=(10, 0))
entry_device = tk.Entry(root, width=30)
entry_device.pack()

tk.Label(root, text="Enrollment Authorization ID").pack(pady=(10, 0))
entry_authorization_id = tk.Entry(root, width=30)
entry_authorization_id.pack()

tk.Label(root, text="Enrollment Authorization Secret").pack(pady=(10, 0))
entry_authorization_secret = tk.Entry(root, width=30, show="*")
entry_authorization_secret.pack()

tk.Button(root, text="Bind Authenticator", command=do_register).pack(pady=8)
tk.Button(root, text="Login (Challenge-Response)", command=do_login).pack(pady=4)

root.mainloop()
