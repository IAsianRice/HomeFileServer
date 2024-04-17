class AddUserPageController:
    def __init__(self, application, model):
        self.model = model
        self.application = application


    # Event handlers for all the buttons.
    def add_user_clicked(self):
        self.model.add_user()
        self.application.app.layout = self.application.page2.get_layout()
    def back_clicked(self):
        pass