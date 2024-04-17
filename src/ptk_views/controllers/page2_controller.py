class Page2Controller:
    def __init__(self, application, model):
        self.application = application
        self.model = model


    # Event handlers for all the buttons.
    def add_user_clicked(self):
        self.application.app.layout = self.application.addUserPage.get_layout()

    def delete_user_clicked(self):
        self.model.delete_user()

    def edit_user_clicked(self):
        self.model.text_area.text = "Button 1 clicked"

    def prev_clicked(self):
        self.application.app.layout = self.application.page1.get_layout()

    def next_clicked(self):
        self.model.text_area.text = "Button 1 clicked"