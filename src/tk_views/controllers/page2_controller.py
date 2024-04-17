class Page2Controller:
    def __init__(self, main_app, model):
        self.main_app = main_app
        self.model = model

    def on_button_click(self):
        # Add Page 2 specific logic here
        self.main_app.page2.label.config(text=self.model.get_page2_data())
        self.main_app.page2.pack_forget()
        self.main_app.page1.show()