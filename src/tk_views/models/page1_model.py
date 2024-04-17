class Page1Model:
    def __init__(self):
        self.page1_data = "Welcome to Page 1!"
        self.server_status = "Stopped"

    def get_page1_data(self):
        return self.page1_data

    def start_server(self):
        # Implement your socket server start logic here
        # For example, create a socket server in a separate thread
        self.server_status = "Running"

    def stop_server(self):
        # Implement your socket server stop logic here
        # For example, stop the socket server thread
        self.server_status = "Stopped"