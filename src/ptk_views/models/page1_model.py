import datetime
from collections import deque

from prompt_toolkit.layout import FormattedTextControl
from prompt_toolkit.widgets import TextArea, Label

from src.socket.SecureSocketServer import SecureSocketServer


class Page1Model:
    def __init__(self, application):
        self.application = application
        self.server_status = Label(text="")
        self.server_local_ip = Label(text="")
        self.server_public_ip = Label(text="")
        self.server_port = Label(text="")
        self.responses = Label(text="")
        self.response_buffer = deque(maxlen=25)

    def refresh(self, app):
        # print(app)
        server: SecureSocketServer = self.application.server
        self.response_buffer.extend(server.get_messages())
        self.responses.text = '\n'.join(map(str, self.response_buffer))
        self.server_status.text = "Server Running" if server.running else "Server Stopped"
        self.server_local_ip.text = f"Hostname (Internal IP): {server.host}"
        self.server_public_ip.text = f"Hostname (External IP): {server.public_ipv4_address}"
        self.server_port.text = f"Port :{server.port}"

