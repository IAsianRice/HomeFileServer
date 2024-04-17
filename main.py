"""
Start Application
"""
import tkinter as tk
from tkinter import ttk
import os.path

from src.ptk_views.main_view import PTKApp
from src.socket.SecureSocketServer import SecureSocketServer
from src.utils.server import Server
from src.tk_views.main_view import MyApp
import rsa
import sys

# server env file
SERVER_FILE = './server.json'

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "console":
        PTKApp()
    else:
        root = tk.Tk()
        root.geometry("800x800")
        app = MyApp(root)
        root.mainloop()




