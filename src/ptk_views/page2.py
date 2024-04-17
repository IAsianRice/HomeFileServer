from prompt_toolkit.layout import HSplit, Window, FormattedTextControl, Layout, VSplit
from prompt_toolkit.widgets import CheckboxList, Box, Label, Button, TextArea, Frame


class Page2:
    def __init__(self, controller):
        self.controller = controller
        self.model = controller.model

        add_user_button = Button("Add User", handler=controller.add_user_clicked)
        delete_user_button = Button("Delete User", handler=controller.delete_user_clicked)
        edit_user_button = Button("Edit User", handler=controller.edit_user_clicked)
        prev_button = Button("Prev", handler=controller.prev_clicked)
        next_button = Button("Next", handler=controller.next_clicked)

        self.layout = Layout(
            HSplit(
                [
                    VSplit(
                        [
                            Box(
                                body=HSplit([add_user_button, delete_user_button, edit_user_button, VSplit([prev_button, next_button])], padding=1),
                                padding=1,
                                style="class:left-pane",
                            ),
                            Box(body=self.model.user_list_frame, padding=1, style="class:right-pane"),
                        ]
                    ),
                ]
            )
        )

    def get_layout(self):
        return self.layout
