import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter
import threading
from datetime import datetime
from tkinter import Text
import firebase_admin
import threading
from datetime import datetime
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

logdinusername = ''
logdinemail = ''
chatID = ''
usernames = ''
recipient_email=''
members = set()
group_name = ''
userID = ''
service_account_key = {
  "type": "service_account",
  "project_id": "chat-room-bac95",
  "private_key_id": "7ac53feb5545393b4e0e0731541e52a389db57f1",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyZHGQ/6ftN1/y\nL30uCLshE+JxByWfTUST94tx3Iu1qHylNZVikfuxotvGPWrcChPuNmN9fWirKqzD\nthQiyHA3QyEvvzFrnIILs4ef4S0Ywty1QL3VRhzGCUGowCF9NcEXE8XAbCSlrVjf\nvLkRhRIUHihCxDfBuMkcSajulcaxQZvb/Iv4qrf9A4ycm+RucDbaXSRtGm1R2GrW\nYXyFQy+mBRG/3HQr57nKEYCNHALAyvlqtdVYCMGBr2ZF9wwV7cUE1DDm4F+D7+/j\n755URGYxHr2QiYnxmfgGwJJ5XguwACHJALP5/tt+hmNWrtEGLnDLBU+n27aBSQIU\nQWQT+IS3AgMBAAECggEAGMt3MXUnTQRWVJ4fIwfZopZV8enRY9vkfUB55ECINp6N\nfJT/B21M83q0W1BsCttnu8NZfrawlqHe03D6SX9cgYHWGgHUB6YAOUohvqoYj4l+\nDb9K41rUYv4kXyUdQn73MJLx+HXPfiui364mdvXs9ljetbD6IvXhFgpy7X5p2HcP\nj+30LmA2nSPePY61VMM+w1Fuy54PXCzwdSg9NpLp9hXVthSPces3JVNmu+duxvR1\ngOns21ZMwgEom8xTOjYHS+NcJ6Buco4Mnwb+xkUfW38OpzndmnXnYfHDdp5SEcXf\nFXIyNej0o/U+JjI1loLvTrrQjdvZwHxzUCQ8xGl3yQKBgQDftGtWObiAl4bcWgDx\nLulbRUzFMtfb/MvGoTdZaxlT2eIbi5CP8bh5ZWkfdVU2HBUQUPp23Sekm5Wa2cdj\nUuGfa4xtX/JhN3NgwmUwulkAaEDpvCZLDDZjvDQuBPMeJCFqW3HgV/qnepDUa1x7\n9ZVO1P62Zb9QdP5PyG/Xtmp+SwKBgQDMJWOCdfLkJGmfjez2BGhgzs/0SkiN8/9i\n+bR0d//bJqpfdNgIIX2al5EisXkZwAVncinTE5B6yTZNkuMowsmN1s9O+tetOAp6\nz0NGMR9Q+GD8JqltJWyFUOVUkLJK/WJNxpyirC93zg8S4jSwRTjwAF1ZE+V+hGck\nuCTvhsbfxQKBgDjJF6YfqNIbpMQypKKUgfAFO2OjcGALX77gFajBIwDCAj9zwhKI\nDYfjUjgGFMdTgZVOuQWLRhDm3acdORvhYhyRtGffPyumY8dgEUe5RfZwgGnUtPO/\n+d5/W8+CuiQgj8rrw5BrRNlWp4UEa8mboXcNYkrysQm/aP7fpmRfjdDZAoGBALiS\nUU7hvzIf7dNRKV4hDBICyievhbu6UDu3Uj0/RXdplP5rEOsBBKPhx1nbpYbvgrNN\nl5z8glNRWqR2WqU+v6ZbAeIBj0BQe8EfZU6wGQVHG8C+X86L2HsMcdusW1bLkraJ\nDJNTJDOofR5woHyCiYEMg1mHUKW7pdmgF9zsOSCVAoGBAKy1uZGYfOeDvEh9scea\nbxyIFLSi4qRdw6II1hVehwx9kJaRiAJYuN2xdMUpe9mepWOgoJwzYAUsDaNFFn+b\nEjPvkFTzN9iHA+FUtgq2OEIBN9m79hS32UKZkjy1zr9tvQpESD5p/LPeryT13hs6\nK3cw+3Dy+izAHvXh1EAlqDt7\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-1f5ry@chat-room-bac95.iam.gserviceaccount.com",
  "client_id": "107186383215321174161",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-1f5ry%40chat-room-bac95.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

cred = credentials.Certificate(service_account_key)
firebase_admin.initialize_app(cred)

db = firestore.client()

class Server:
    callback_done = threading.Event()
    Message_Callback = None

    
    @staticmethod
    def on_snapshot(doc_snapshot, changes, read_time):
        #print('snapshot saved')
        if Server.Message_Callback != None:
            #print('callback')
            Server.Message_Callback()
        Server.callback_done.set()
        
    @staticmethod
    def Login(email, password):
        doc_ref = db.collection('Users').where(filter=FieldFilter('Email', '==', email)).where(filter=FieldFilter('Password', '==', password)).limit(1).get()

        if len(doc_ref) != 0: 

            return True
        else:
            return False

          
    @staticmethod
    def get_private_chat_id(logged_in_email, recipient_email):
        try:
            query = db.collection('PrivateChat').where(filter=FieldFilter('Creator_email', '==', logged_in_email)).where(filter=FieldFilter('Recipient_email', '==', recipient_email)).limit(1).get()
            for doc in query:
                return doc.id
            return None
        except Exception as e:
            #print(f"Error getting private chat ID: {e}")
            return None
    
    
    @staticmethod
    def get_chat_type(chat_id):
        try:
            group_chat_ref = firestore.client().collection('GroupChat').document(chat_id).get()
            if group_chat_ref.exists:
                return 'group'

            private_chat_ref = firestore.client().collection('PrivateChat').document(chat_id).get()
            if private_chat_ref.exists:
                return 'private'

            return None

        except Exception as e:
            print(f"Error getting group type: {e}")
            return None
          
          
    @staticmethod
    def save_message(chat_id, sender, message, chat_type):
        try:
            timestamp = datetime.now()

            data = {
                'chat_id': chat_id,
                'sender': sender,
                'message': message,
                'timestamp': timestamp
            }
            if chat_type == 'private':
                collection_ref = firestore.client().collection('PrivateChat')
            elif chat_type == 'group':
                collection_ref = firestore.client().collection('GroupChat')
            else:
                raise ValueError("Invalid chat type. Must be 'private' or 'group'.")

            messages_ref = collection_ref.document(chat_id).collection('messages')
            messages_ref.add(data)

            #print("Message saved successfully.")
        except Exception as e:
            print(f"Error saving message: {e}")

            
    @staticmethod
    def create_user(username, email, password):
        try:
            user_ref = db.collection('Users').document(email)
            if user_ref.get().exists:
                #print("User already exists.")
                return False
            user_ref.set({
                'Password': password,
                'Username': username,
                'Email': email
            })
            #print("User created successfully.")
            return True
        except Exception as e:
            #print(f"Error creating user: {e}")
            return False

          
    @staticmethod
    def get_GroupNames(User_email):
        try:
            admin_query = db.collection('GroupChat').where(filter=FieldFilter('Admin_email', '==', User_email)).get()

            member_query = db.collection('GroupChat').where(filter=FieldFilter('members', 'array_contains', User_email)).get()

            groupnames = set()

            for doc in admin_query:
                chat_name = doc.get('Chat_name')
                groupnames.add(chat_name)

            for doc in member_query:
                chat_name = doc.get('Chat_name')
                groupnames.add(chat_name)

            return groupnames

        except Exception as e:
            print(f"Error getting group names: {e}")
            return []
   
  
    @staticmethod
    def get_emails(recipient_email):
        try:
            query = db.collection('PrivateChat').where(filter=FieldFilter('Recipient_email', '==', recipient_email)).get()
            query2 = db.collection('PrivateChat').where(filter=FieldFilter('Creator_email', '==', recipient_email)).get()
            usernames = set()
            for doc in query:
                creator_email = doc.get('Creator_email')
                usernames.add(creator_email)
            for doc in query2:
                recipient_email = doc.get('Recipient_email')
                usernames.add(recipient_email)
            return set(usernames)
        except Exception as e:
            #print(f"Error getting usernames: {e}")
            return []


    @staticmethod
    def get_messages(chatID, chat_type):
        try:
            if chat_type == 'group':
                messages_ref = db.collection('GroupChat').document(chatID).collection('messages')
            elif chat_type == 'private':
                messages_ref = db.collection('PrivateChat').document(chatID).collection('messages')
            else:
                raise ValueError("Invalid chat_type. Must be 'group' or 'private'.")

            query = messages_ref.order_by('timestamp').stream()
            messages = []
            for doc in query:
                message_data = doc.to_dict()
                timestamp = message_data.get('timestamp', '')
                sender = message_data.get('sender', '')
                message_text = message_data.get('message', '')
                formatted_message = f"{timestamp}: {sender}: {message_text}"
                messages.append(formatted_message)
            return messages
        except Exception as e:
            print(f"Error getting messages: {e}")
            return []
          
          
    @staticmethod
    def add_member_to_group(chatID, new_member_email):
        try:
            group_ref = db.collection('GroupChat').document(chatID)

            group_data = group_ref.get().to_dict()
            if group_data:
                members = group_data.get('members', [])
            else:
                members = []

            if new_member_email in members:
                print("Error: Member already exists in the group.")
            else:
                members.append(new_member_email)

                group_ref.update({'members': members})

                return True
        except Exception as e:
            print(f"Error adding user to group: {e}")
            return False

          
    @staticmethod
    def create_group_chat(group_name,admin_email,members):
        data = {
            'Admin_email':admin_email,
            'Chat_name': group_name,
            'timestamp': datetime.now(),  
            'members': list(members)
        }

        group_ref = db.collection('GroupChat').document()

        group_ref.set(data)

        messages_ref = group_ref.collection('messages')
        messages_ref.add({
            'content': 'Welcome to the group chat!',  
            'sender': 'System',  
            'timestamp': datetime.now(),  
        })

        return group_ref.id


    @staticmethod
    def get_user_ids():
        try:
            doc_ref = db.collection('Users')
            docs = doc_ref.stream()

            user_ids = [doc.id for doc in docs]

            return user_ids
        except Exception as e:
            #print(f"Error getting user IDs: {e}")
            return []

          
    @staticmethod
    def new_private_chat(creator_email, recipient_email):
            try:
                existing_chat_id = Server.get_private_chat_id(creator_email, recipient_email)
                if existing_chat_id:
                    print("Private chat already exists.")
                    return existing_chat_id
                chat_ref = db.collection('PrivateChat').document()
                chat_id = chat_ref.id
                chat_ref.set({
                    'Chat_id': chat_id,
                    'Creator_email': creator_email,
                    'Recipient_email': recipient_email
                })
                messages_ref = chat_ref.collection('messages')
                create_private_buttons(Private_sidebar_frame, Server.get_emails(logdinemail))
                #print("Private chat created successfully.")
                return chat_id
            except Exception as e:
                #print(f"Error creating private chat: {e}")
                return None
                
    @staticmethod
    def get_group_chat_id(group_name):
        group_ref = db.collection('GroupChat')

        query = group_ref.where('Chat_name', '==', group_name).limit(1).get()

        for doc in query:
            return doc.id

        return None


    @staticmethod
    def get_private_chat_id(creator_email, recipient_email):
        try:
            creator_filter = FieldFilter('Creator_email', 'in', [creator_email, recipient_email])
            recipient_filter = FieldFilter('Recipient_email', 'in', [creator_email, recipient_email])
            
            query = db.collection('PrivateChat').where(filter=creator_filter).where(filter=recipient_filter).limit(1).get()
            
            for doc in query:
                return doc.id
            
            return None
        except Exception as e:
            #print(f"Error getting private chat ID: {e}")
            return None
        

    @staticmethod
    def listen_for_updates(chatID, callback):
        print("listen for updates triggered")
        chat_type = Server.get_chat_type(chatID)
        try:
            if chat_type == 'private':
                messages_ref = db.collection('PrivateChat').document(chatID).collection('messages')
            elif chat_type == 'group':
                messages_ref = db.collection('GroupChat').document(chatID).collection('messages')

            def on_snapshot(doc_snapshot, changes, read_time):
                for doc in doc_snapshot:
                    print(f'Received update for document: {doc.id}')
                    data = doc.to_dict()
                    print(f'Updated data: {data}')
                    if data:
                        callback(chatID)  
                        return

            messages_ref.on_snapshot(on_snapshot)
        except Exception as e:
            print(f"Error in listen_for_updates: {e}")
    
    @staticmethod
    def listen_for_new_chats(callback):
        print("listen for new chats triggered")
        try:
            private_chats_ref = db.collection('PrivateChat')
            group_chats_ref = db.collection('GroupChat')

            def on_snapshot(snapshot, changes, read_time):
                for change in changes:
                    if change.type.name == 'ADDED':
                        chatID = change.document.id
                        print(f'New chat created: {chatID}')
                        callback(chatID)  
                    elif change.type.name == 'REMOVED':
                        chatID = change.document.id
                        print(f'Chat removed: {chatID}')
                        callback(chatID)

            private_chats_ref.on_snapshot(on_snapshot)
            group_chats_ref.on_snapshot(on_snapshot)
        except Exception as e:
            print(f"Error in listen_for_new_chats: {e}")


def login_window():
    global login_win
    login_win = tk.Toplevel()
    login_win.title('Login')
    login_win.geometry('300x400')
    window.withdraw()

    lbl_email = ttk.Label(login_win, text='Email:')
    lbl_email.pack(pady=10, padx=10)
    entry_email = ttk.Entry(login_win)
    entry_email.pack(pady=10, padx=10)

    lbl_password = ttk.Label(login_win, text='Password:')
    lbl_password.pack(pady=10, padx=10)
    entry_password = ttk.Entry(login_win, show='*')
    entry_password.pack(pady=10, padx=10)

    def on_login():
        email = entry_email.get()
        password = entry_password.get()

        if Server.Login(email, password):
            login_win.destroy()
            window.deiconify()

            create_private_buttons(Private_sidebar_frame, Server.get_emails(email)) 
            create_group_buttons(Group_sidebar_frame, Server.get_GroupNames(email))
            on_login_click(email, password)

        else:
            messagebox.showerror('Error', 'Invalid username or password')
        
        
        #create_private_buttons(Private_sidebar_frame, Server.get_emails())
    
    
    def on_signup():
        login_win.destroy()
        on_signup_click()

    btn_login = ttk.Button(login_win, text='Login', command=on_login)
    btn_login.pack(pady=10, padx=10)

    btn_signup = ttk.Button(login_win, text='Signup', command=on_signup)
    btn_signup.pack(pady=10, padx=10)


def create_private_buttons(frame, emails):
    for widget in frame.winfo_children():
        widget.destroy()

    for email in emails:
        btn_email = ttk.Button(frame, text=email, command=lambda email=email: on_private_button_click(email))
        btn_email.pack(fill="both", expand=True)

def create_group_buttons(frame, group_names):
    for widget in frame.winfo_children():
        widget.destroy()

    for group_name in group_names:
        btn_group = ttk.Button(frame, text=group_name, command=lambda name=group_name: on_group_button_click(name))  
        btn_group.pack(fill="both", expand=True)


def on_group_button_click(group_name):
    global chatID
    global recipient_email  
    chatID = Server.get_group_chat_id(group_name)  
    print(chatID)
    update_chat_id_label(chatID,group_name)
    if chatID:
        display_messages(chatID)
        start_listening(chatID)
        return chatID
    else:
        print("Invalid chat")

def on_private_button_click(email):
    global chatID
    global recipient_email
    recipient_email = email
    chatID=Server.get_private_chat_id(logdinemail,recipient_email)
    #print(chatID)
    update_chat_id_label(chatID,group_name)
    if chatID:
        display_messages(chatID)
        Server.Message_Callback = display_messages
        start_listening(chatID)
        create_private_buttons(Private_sidebar_frame, Server.get_emails(logdinemail))
        #print("chatID: {chatID} updated.")
        return chatID
    else:
        print("Invalid chat")

def start_listening(chatID):
    Server.listen_for_updates(chatID, display_messages)

    Server.listen_for_new_chats(new_chat_callback)


def on_login_click(email, password):
    global logdinemail, usernames  
    if Server.Login(email, password):
        logdinemail = email  
        usernames = Server.get_emails(logdinemail)  
        login_win.destroy()
        window.deiconify()
        #create_private_buttons(Private_sidebar_frame, usernames) 
        #create_group_buttons(Group_sidebar_frame, Server.get_GroupNames(email))
        #display_messages(chatId)
    else:
        messagebox.showerror('Error', 'Invalid username or password')

        
def create_user(password, password_check, username, email):
    if username == '':
        messagebox.showerror('Error', 'Username is empty')
        return
        
    if email == '':
        messagebox.showerror('Error', 'Email is empty')
        return
        
    if password == '' or password_check == '':
        messagebox.showerror('Error', 'Password is empty')
        return
        
    if password != password_check:
        messagebox.showerror('Error', 'Passwords do not match')
        return
    else:
        Server.create_user(username, email, password)
        login_window()
        signup_win.destroy()
        return 'signed up'


def on_signup_click():
    global signup_win
    signup_win = tk.Toplevel()
    signup_win.title('Signup')
    signup_win.geometry('400x600')
    login_win.destroy()
    window.withdraw()

    lbl_username = ttk.Label(signup_win, text='Username:')
    lbl_username.pack(pady=10, padx=10)
    entry_username = ttk.Entry(signup_win)
    entry_username.pack(pady=10, padx=10)
    
    lbl_email = ttk.Label(signup_win, text='Email:')
    lbl_email.pack(pady=10, padx=10)
    entry_email = ttk.Entry(signup_win)
    entry_email.pack(pady=10, padx=10)

    lbl_password = ttk.Label(signup_win, text='Enter Password:')
    lbl_password.pack(pady=10, padx=10)
    entry_password = ttk.Entry(signup_win)
    entry_password.pack(pady=10, padx=10)
    
    lbl_passwordcheck = ttk.Label(signup_win, text='Confirm Password:')
    lbl_passwordcheck.pack(pady=10, padx=10)
    entry_passwordcheck = ttk.Entry(signup_win)
    entry_passwordcheck.pack(pady=10, padx=10)
    
    btn_create_user = ttk.Button(signup_win, text='Signup', command=lambda: create_user(entry_password.get(), entry_passwordcheck.get(), entry_username.get(), entry_email.get()))
    btn_create_user.pack(pady=10, padx=10)


def on_click_private_chat():
    global create_private_chat_window, lbl_add_user
    create_private_chat_window = tk.Toplevel(window)
    create_private_chat_window.title('Create Private Chat')
    create_private_chat_window.geometry('200x200')

    def on_window_close():
        lbl_add_user.pack_forget()
        create_private_chat_window.destroy()

    create_private_chat_window.protocol("WM_DELETE_WINDOW", on_window_close)

    lbl_add_user = ttk.Label(create_private_chat_window, text='Add recipient email')
    lbl_add_user.pack()
    recipient_email_entry = tk.Entry(create_private_chat_window)
    recipient_email_entry.pack()
    btn_create_chat = ttk.Button(create_private_chat_window, text='Create', command=lambda: on_click_private_chat_open(recipient_email_entry))
    btn_create_chat.pack()


def on_click_private_chat_open(entry):
    recipient_email = entry.get()
    chatID = Server.new_private_chat(logdinemail, recipient_email)
    if chatID:
        #print(f"Private chat created successfully with ID: {chatID}")
        create_private_chat_window.destroy()
        create_chat_window.destroy()  
        display_messages(chatID)  
        return recipient_email
    else:
        print("Failed to create private chat")


def new_chat_callback(chatID):
    try:
        chat_type = Server.get_chat_type(chatID)
        if chat_type == 'private':
            create_private_buttons(Private_sidebar_frame, Server.get_emails(logdinemail))
        elif chat_type == 'group':
            create_group_buttons(Group_sidebar_frame, Server.get_GroupNames(logdinemail))
        else:
            print(f"Unknown chat type for chatID: {chatID}")
    except Exception as e:
        print(f"Error handling new chat: {e}")


def on_click_group_chat():
    global create_group_chat_window, lbl_add_user_group
    create_group_chat_window = tk.Toplevel(window)
    create_group_chat_window.title('Create Group Chat')
    create_group_chat_window.geometry('200x200')

    def on_window_close():
        lbl_add_user_group.pack_forget()
        create_group_chat_window.destroy()

    create_group_chat_window.protocol("WM_DELETE_WINDOW", on_window_close)

    lbl_enter_group_name = ttk.Label(create_group_chat_window, text='Choose chat name', background='#add8e6')
    lbl_enter_group_name.pack()

    group_name = tk.Entry(create_group_chat_window)
    group_name.pack()

    lbl_add_user_group = ttk.Label(create_group_chat_window, text='Add recipient email')
    lbl_add_user_group.pack()

    email = tk.Entry(create_group_chat_window)
    email.pack()

    btn_create_chat = ttk.Button(create_group_chat_window, text='Create', command=lambda: on_click_group_chat_open(group_name, email))
    btn_create_chat.pack()


def on_click_group_chat_open(group_name_entry, email_entry):
    global group_name
    group_name = group_name_entry.get()
    recipient_email = email_entry.get()
    members.add(recipient_email)

    Server.create_group_chat(group_name, logdinemail,members)
    
    if group_name and recipient_email:
        #print("group_name: ",group_name,"recipient_email: ",recipient_email)
        create_group_chat_window.destroy()
        create_chat_window.destroy()
        start_listening(Server.get_group_chat_id(chatID))
    else:
        print("Failed to create group chat")


def on_click_create_chat():
    global create_chat_window
    create_chat_window = tk.Toplevel()
    create_chat_window.title('Create Chat')
    create_chat_window.geometry('200x200')

    lbl_ccw = ttk.Label(create_chat_window, text='Choose type of chat', background='#add8e6')
    lbl_ccw.pack()

    btn_gc = ttk.Button(create_chat_window, text='Group Chat', command=on_click_group_chat)
    btn_gc.pack()

    btn_pc = ttk.Button(create_chat_window, text='Private Chat', command=on_click_private_chat)
    btn_pc.pack()

    global chat_id
    chat_id = Server.get_private_chat_id(logdinemail, recipient_email)

def display_messages(chatID):
    txtDisplay.config(state='normal')  
    txtDisplay.delete("1.0", tk.END)

    messages = Server.get_messages(chatID,Server.get_chat_type(chatID))
    if messages:
        sorted_messages = sorted(messages, key=lambda x: x.split(':', 1)[0])

        txtDisplay.tag_configure('email', font=('Arial', 10), foreground='blue')
        txtDisplay.tag_configure('content', font=('Arial', 12))

        for message in sorted_messages:
            timestamp, sender_email, content = message.rsplit(':', 2)
            sender_name = 'Some Unknown User' if sender_email in ("", " ", "None") else sender_email

            alignment = 'right' if sender_email == logdinemail else 'left'

            email_tag = 'email' if alignment == 'left' else 'content'
            content_tag = 'content' if alignment == 'left' else 'email'

            txtDisplay.insert(tk.END, f"{sender_name}: ", email_tag)
            txtDisplay.insert(tk.END, f"{content}\n", content_tag)

    else:
        txtDisplay.insert(tk.END, "No messages to display.")

    txtDisplay.config(state='disabled')
    txtDisplay.see(tk.END)

def on_click_send_message():
    message = txtMessage.get("1.0", "end").strip()
    txtDisplay.insert(tk.END,"\n")
    
    if message:
        if chatID:
            chat_type = Server.get_chat_type(chatID)
            Server.save_message(chatID, logdinemail, message,chat_type)

            message_line = f"{logdinemail}: {message}\n" 

            alignment = 'right' if logdinemail == recipient_email else 'left'

            txtDisplay.config(state='normal')  
            txtDisplay.insert(tk.END, message_line, alignment)
            txtDisplay.config(state='disabled')  

            txtMessage.delete("1.0", tk.END)
        else:
            messagebox.showerror('Error', 'Invalid chat')
    else:
        messagebox.showerror('Error', 'Message cannot be empty')

def on_click_close():
    window.destroy()

def add_user_to_group():

    create_chat_window = tk.Toplevel()
    create_chat_window.title('Add a new member')
    create_chat_window.geometry('200x200')
    create_chat_window.configure(bg='#add8e6')

    label = ttk.Label(create_chat_window, text="Enter user's email", background='#add8e6')
    label.pack()

    email_entry = tk.Entry(create_chat_window)
    email_entry.pack()

    add_memb_button = ttk.Button(create_chat_window, text="Add", command=lambda: Server.add_member_to_group(chatID, email_entry.get()))
    add_memb_button.pack()

def Refresh():
    create_group_buttons(Group_sidebar_frame, Server.get_GroupNames(logdinemail))
    create_private_buttons(Private_sidebar_frame, Server.get_emails(logdinemail)) 

window = tk.Tk()
window.geometry('600x400')
window.configure(bg='#add8e6')
width, height = window.winfo_screenwidth(), window.winfo_screenheight()
window.geometry('%dx%d+0+0' % (width,height))
window.title('Chat App')

state = ""
window.rowconfigure(0, weight=3)
window.rowconfigure(1, weight=1)
window.rowconfigure(2, weight=1)
window.rowconfigure(3, weight=6)
window.rowconfigure(4, weight=1)
window.rowconfigure(5, weight=6)
window.rowconfigure(6, weight=4)
window.columnconfigure(0, weight=6)
window.columnconfigure(1, weight=12)
window.columnconfigure(2, weight=1)

message_listbox = tk.Listbox(window)
message_listbox.grid(row=1, column=1, rowspan=4, columnspan=2, sticky="nsew")

btn_new_chat = ttk.Button(window, text='Add New Chat', command=on_click_create_chat)
btn_new_chat.grid(row=1, column=0, sticky="nsew")
btn_new_message = ttk.Button(window, text='Send', command=on_click_send_message)
btn_new_message.grid(row=6, column=2, sticky="nsew")
btn_add_user = ttk.Button(window, text='Add Members',command=add_user_to_group)
btn_add_user.grid(row=0, column=2,sticky="nsew")
btnRefresh = ttk.Button(window, text='Refresh',command=Refresh)
btnRefresh.grid(row=6, column=0, sticky="new")
btn_close = ttk.Button(window, text='Close', command=on_click_close)
btn_close.grid(row=6, column=0, sticky="ew")
lbl_chats = ttk.Label(window, text="Chats", background='#79b6c9')
lbl_chats.grid(row=0, column=0, sticky='nsew')

chat_id_var = tk.StringVar()
chat_id_var.set("ChatID: ")

def update_chat_id_label(chat_id,group_name):
    if (Server.get_chat_type(chat_id) =='group'):
        chat_id_var.set(f"group name: {group_name}")
    else:
        chat_id_var.set(f"ChatID: {chat_id}")

lbl_username = ttk.Label(window, textvariable=chat_id_var, background='#add8e6')
lbl_username.grid(row=0, column=1, columnspan=1, sticky='nsew')

Private_sidebar_frame = customtkinter.CTkScrollableFrame(window, corner_radius=0)
Private_sidebar_frame.grid(row=3, column=0, sticky='nsew')
private_chats_label = ttk.Label(window, text="Private Chats", background='#add8e6')
private_chats_label.grid(row=2,column=0, sticky='nsew')

Group_sidebar_frame = customtkinter.CTkScrollableFrame(window, corner_radius=0)
Group_sidebar_frame.grid(row=5, column=0, sticky='nsew')
group_chats_label = ttk.Label(window, text="Group Chats", background='#add8e6')
group_chats_label.grid(row=4,column=0, sticky='nsew')


txtMessage = customtkinter.CTkTextbox(window, height=50)
txtMessage.grid(row=6, column=1,columnspan=1, sticky="nsew", pady=10)


txtDisplay = Text(window)

txtDisplay.grid(row=1, column=1, rowspan=5, columnspan=2, sticky="nsew")

txtDisplay.configure(state='disabled')

login_window()
window.mainloop()

