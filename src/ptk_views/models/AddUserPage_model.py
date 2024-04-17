import datetime

from prompt_toolkit.layout import FormattedTextControl
from prompt_toolkit.widgets import TextArea, Label, CheckboxList

from src.utils.utility import create_user_directory


class AddUserPageModel:
    def __init__(self, application):
        self.application = application
        self.roles_list = [("Admin", "Administrator"),("User", "Regular User")]
        self.username_textarea = TextArea(text="")
        self.password_textarea = TextArea(text="")
        self.role_checkboxList = CheckboxList(
            values=self.roles_list,
        )
        self.role_checkboxList.multiple_selection = False

    def refresh(self, app):
        # print(app)
        pass

    def add_user(self):
        selectedRole = [item for item in self.roles_list if item[0] == self.role_checkboxList.current_value]
        self.application.users.add_user(self.username_textarea.text, self.password_textarea.text, selectedRole[0][0])
        create_user_directory(self.username_textarea.text)
        self.clear_entries()

    def clear_entries(self):
        self.username_textarea.text = ""
        self.password_textarea.text = ""

