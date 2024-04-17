import threading

from prompt_toolkit.application import Application
from prompt_toolkit.application.current import get_app
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import VSplit, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.widgets import Dialog, Label, Button
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous

from src.ptk_views.AddUserPage import AddUserPage
from src.ptk_views.controllers.AddUserPage_controller import AddUserPageController
from src.ptk_views.controllers.page1_controller import Page1Controller
from src.ptk_views.controllers.page2_controller import Page2Controller
from src.ptk_views.models.AddUserPage_model import AddUserPageModel
from src.ptk_views.models.page1_model import Page1Model
from src.ptk_views.models.page2_model import Page2Model
from src.ptk_views.page1 import Page1
from src.ptk_views.page2 import Page2
from src.socket.SecureSocketServer import SecureSocketServer
from src.socket.api.SocketAPI import SocketAPI
from src.utils.users import Users


class PTKApp:
    def __init__(self):
        kb = KeyBindings()

        self.api = SocketAPI(self)
        self.server = SecureSocketServer(self.api, 7000)
        self.users = Users()

        @kb.add('c-q')
        def exit_(event):
            event.app.exit()

        kb.add("tab")(focus_next)
        kb.add("s-tab")(focus_previous)
        self.addUserPage_model = AddUserPageModel(self)
        self.page1_model =       Page1Model(self)
        self.page2_model =       Page2Model(self)

        self.addUserPage_controller = AddUserPageController(self, self.addUserPage_model)
        self.page1_controller = Page1Controller(self, self.page1_model)
        self.page2_controller = Page2Controller(self, self.page2_model)

        self.addUserPage = AddUserPage(self.addUserPage_controller)
        self.page1 = Page1(self.page1_controller)
        self.page2 = Page2(self.page2_controller)

        def refresh(app):
            self.page1_model.refresh(app)
            self.page2_model.refresh(app)

        self.app = Application(key_bindings=kb, layout=self.page1.get_layout(), full_screen=True, refresh_interval=0.5, on_invalidate=refresh)
        self.app.run()

        self.server.end_service()