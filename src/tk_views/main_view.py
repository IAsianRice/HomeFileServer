from tkinter import ttk
from src.tk_views.page1 import Page1
from src.tk_views.page2 import Page2
from src.tk_views.controllers.page1_controller import Page1Controller
from src.tk_views.controllers.page2_controller import Page2Controller
from src.tk_views.models.page1_model import Page1Model
from src.tk_views.models.page2_model import Page2Model
class MyApp:
    def __init__(self, root):
        self.root = root
        root.title("My Tkinter App")

        #self.notebook = ttk.Notebook(root)
        self.page1_model = Page1Model()
        self.page2_model = Page2Model()

        self.page1_controller = Page1Controller(self, self.page1_model)
        self.page2_controller = Page2Controller(self, self.page2_model)

        self.page1 = Page1(self.root, self.page1_controller)
        self.page2 = Page2(self.root, self.page2_controller)

        self.page1.show()  # Show the first page initially

        #self.notebook.add(self.page1.frame, text="Page 1")
        #self.notebook.add(self.page2.frame, text="Page 2")

        #self.notebook.pack(expand=True, fill="both")