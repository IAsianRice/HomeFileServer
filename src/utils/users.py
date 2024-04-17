import uuid

from src.utils.utility import read_json_file, write_json_file, hash_password, verify_password

FILENAME = "userdata.json"

class Users:
    def __init__(self):
        self.data = read_json_file(FILENAME)
        if not self.data:
            self.data = []
        write_json_file(self.data, FILENAME)
        self.authenticated_users = dict()

    def add_user(self, username, password, role):
        user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'password': hash_password(password).decode('utf-8'),
            'role': role
        }
        self.data.append(user_data)
        write_json_file(self.data, FILENAME)

    def delete_user(self, id):
        self.data = [item for item in self.data if item['id'] != id]
        write_json_file(self.data, FILENAME)

    def get_users(self):
        return self.data

    def edit_user(self, index):
        pass

    def is_conn_auth(self, conn):
        return self.authenticated_users[conn]

    def login(self, username: str, password: str) -> bool:
        found_user = None
        for user in self.data:
            if user['username'] == username:
                found_user = user
        if found_user is not None and verify_password(password.encode('utf-8'), found_user['password'].encode('utf-8')):
            return True
        return False

    #TODO: Make it more robust making types and whatever
    def is_admin(self, username: str) -> bool:
        found_user = None
        for user in self.data:
            if user['username'] == username:
                found_user = user
        return found_user['role'] == 'Admin'


