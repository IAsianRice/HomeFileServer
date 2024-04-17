class Page1Controller:
    def __init__(self, application, model):
        self.model = model
        self.application = application


    # Event handlers for all the buttons.
    def start_server_clicked(self):
        self.application.server.start_server()

    def stop_server_clicked(self):
        self.application.server.end_service()
        #self.application.app.exit()

    def next_clicked(self):
        self.application.app.layout = self.application.page2.get_layout()

    def prev_clicked(self):
        self.model.text_area.text = "Button 3 clicked"

    def exit_clicked(self):
        self.model.get_app().exit()