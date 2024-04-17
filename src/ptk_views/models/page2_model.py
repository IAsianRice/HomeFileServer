import datetime
from prompt_toolkit.layout import FormattedTextControl
from prompt_toolkit.widgets import TextArea, Label, CheckboxList, Frame


class Page2Model:
    def __init__(self, application):
        self.application = application
        self.user_list = list()
        self.user_checkboxList = Label(text="No users registered")
        self.user_list_frame = Frame(self.user_checkboxList)

    def refresh(self, app):
        if len(self.application.users.get_users()) != len(self.user_list):
            self.user_list = list()
            if len(self.application.users.get_users()) == 0:
                self.user_checkboxList = Label(text="No users registered")
            else:
                for user in self.application.users.get_users():
                    self.user_list.append((user['id'], f"{user['username']}:{user['role']}"))
                self.user_checkboxList = CheckboxList(
                    values=self.user_list,
                )
            self.user_list_frame.body = self.user_checkboxList


    def delete_user(self):
        if(len(self.user_list) > 0):
            for id in self.user_checkboxList.current_values:
                self.application.users.delete_user(id)