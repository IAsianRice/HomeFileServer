import tkinter as tk
from tkinter import ttk


class Page1(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.label = ttk.Label(self, text=self.controller.model.get_page1_data())
        self.button = ttk.Button(self, text="Go to Page 2", command=self.controller.on_button_click)

        self.label.grid(row=0, column=0, pady=10)
        self.button.grid(row=1, column=0, pady=10)

    def show(self):
        self.pack(fill="both", expand=True)
        self.lift()
