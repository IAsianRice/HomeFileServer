from prompt_toolkit.layout import HSplit, Window, FormattedTextControl, Layout, VSplit
from prompt_toolkit.widgets import CheckboxList, Box, Label, Button, TextArea, Frame

from src.ptk_views.models.page1_model import Page1Model


class Page1:
    def __init__(self, controller):
        self.controller = controller
        self.model: Page1Model = controller.model

        start_server_btn = Button("Start Server", handler=controller.start_server_clicked)
        stop_server_btn = Button("Stop Server", handler=controller.stop_server_clicked)
        next_btn = Button("Next Page", handler=controller.next_clicked)
        prev_btn = Button("Prev Page", handler=controller.prev_clicked)
        button4 = Button("Exit", handler=controller.exit_clicked)

        self.layout = Layout(
            HSplit(
                [
                    VSplit(
                        [
                            Box(
                                body=HSplit([start_server_btn,
                                             stop_server_btn,
                                             VSplit([prev_btn, next_btn]),
                                             button4],
                                            padding=1),
                                padding=1,
                                style="class:left-pane",
                            ),
                            Box(body=Frame(HSplit([self.model.server_status, self.model.server_local_ip, self.model.server_public_ip, self.model.server_port])), padding=1, style="class:right-pane"),
                            Box(body=Frame(self.model.responses), padding=1, style="class:right-pane"),
                        ]
                    ),
                ]
            )
        )


    def get_layout(self):
        return self.layout
