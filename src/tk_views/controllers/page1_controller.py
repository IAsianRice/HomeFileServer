class Page1Controller:
    def __init__(self, main_app, model):
        self.main_app = main_app
        self.model = model

    def on_button_click(self):
        # Add Page 1 specific logic here
        self.main_app.page1.label.config(text=self.model.get_page1_data())
        self.main_app.page1.pack_forget()
        self.main_app.page2.show()