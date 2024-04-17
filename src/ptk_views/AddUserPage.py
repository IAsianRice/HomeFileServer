from prompt_toolkit.layout import HSplit, Window, FormattedTextControl, Layout, VSplit
from prompt_toolkit.widgets import CheckboxList, Box, Label, Button, TextArea, Frame


class AddUserPage:
    def __init__(self, controller):
        self.controller = controller
        self.model = controller.model

        add_user_button = Button("Add User", handler=controller.add_user_clicked)
        back_button = Button("Back", handler=controller.back_clicked)

        self.layout = Layout(
                    HSplit(
                        [
                            VSplit(
                                [
                                    Box(
                                        body=HSplit([add_user_button, back_button], padding=1),
                                        padding=1,
                                        style="class:left-pane",
                                    ),
                                    Box(HSplit([
                                        Label(text="Username:"),
                                        Frame(self.model.username_textarea),
                                        Label(text="Password:"),
                                        Frame(self.model.password_textarea),
                                        Label(text="Role:"),
                                        Frame(self.model.role_checkboxList),
                                    ], padding=1)),
                                ]
                            ),
                        ]
                    )
                )


    def get_layout(self):
        return self.layout
