from socket import *
import threading
#Server

#Dict of connect clients
clients = {}

#File containing users and the thread lock
user_file = "users.txt"
lock = threading.Lock()

#Dict holding messages for logged off users
#key is username, value is list of messages
messages = {}

#List of commands
#maybe changed later for admin
commands = {
    "/who": "Lists all connected users",
    "/exit": "Disconnects you from the server",
    "/tell <user> <message>": "Sends a private message to a user",
    "/motd": "Displays the message of the day",
    "/me <message>": "Sends an emote to all users",
}

#MOTD
motdmsg = " MOTD - Welcome to the chat server, use `/help` to begin!\n"

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

#Determines if the user has previously logged in with correct credentials
def authenticate_user(username, password):
    #This return isn't intuitive, it's just the last permutation
    if username in clients:
        return False, True

    with lock:
        with open(user_file, 'r') as f:
            for line in f:
                _username, _password = line.strip().split(':')
                #When all information exists, return True, True
                #Return two bools for case when user already exists but didn't get password correct
                if username == _username and password == _password:
                    return True, True
                #Existing user, wrong password
                elif username == _username:
                    return True, False
    #New user
    return False, False

def add_user(username, password):
    with lock:
        with open(user_file, 'a') as f:
            f.write(f"{username}:{password}\n")

def broadcast(message):
    for client in clients.values():
        client.send(message.encode())

def msg_all_but_messenger(username, message):
    for user, client in clients.items():
        if user != username:
            client.send(message.encode())

def catchup_messages(username):
    if username in messages:
        msg = "You have private messages:\n"
        clients[username].send(msg.encode())
        for message in messages[username]:
            clients[username].send(message.encode())
        messages.pop(username)

def who(clientConn):
    with lock:
        clientConn.send("Users logged in:\n".encode())
        for user in clients.keys():
            clientConn.send(f"{user}\n".encode())
    pass

def exit(clientConn, username):
    with lock:
        clients.pop(username)
    print(f"Disconnected from {username}")
    clientConn.close()
    return

def tell(srcUser, destUser, message):
    message = f"{srcUser} tells you: {message}\n"

    if destUser in clients:
        clients[destUser].send(message.encode())
        return

    #check all registered users
    with lock:
        with open(user_file, 'r') as f:
            for line in f:
                _username, _password = line.strip().split(':')
                if destUser == _username:
                    if destUser in messages:
                        messages[destUser].append(message)
                    else:
                        messages[destUser] = [message]
                    return

def motd(clientConn):
    clientConn.send(motdmsg.encode())

def me(username, message):
    emote = f"*{username} {message}\n"
    msg_all_but_messenger(username, emote)

def help(clientConn):
    helpmsg = "Commands:\n"
    clientConn.send(helpmsg.encode())
    for command, description in commands.items():
        helpmsg = f"{command}: {description}\n"
        clientConn.send(helpmsg.encode())

def kick():
    pass

def ban():
    pass

def unban():
    pass

def login(conn):
    print("Logging in...")

    #Send a message telling the client to enter username
    usermsg = "Enter your username:\n"
    conn.send(usermsg.encode())
    username = getLine(conn).strip('\n')

    #send a message telling the client to enter password
    passmsg = "Enter your password:\n"
    conn.send(passmsg.encode())
    password = getLine(conn).strip('\n')
    is_user,is_pass = authenticate_user(username, password)

    #User is already logged in, but another is trying to log in as them
    if not is_user and is_pass:
        auth_msg = "Someone is already logged in as this user\n"
        conn.send(auth_msg.encode())
        return False, username

    #Unsuccessful login
    if is_user and not is_pass:
        auth_msg = "You're password was incorrect\n"
        conn.send(auth_msg.encode())
        return False, username

    #Add new user to file of users
    if not is_user and not is_pass:
        add_user(username, password)

    #Successful login
    return True, username


#threads for each client
def handleClient(clientConn, peerAddr):
    print("Client Connected")
    #login protocol
    attempts = 0
    while True:
        attempts += 1

        print ("Login Attempt: ", attempts)
        loginResult, username = login(clientConn)

        if loginResult:
            break

    print("Client logged in successfully")
    loggedinMsg = "Logged in\n"
    clientConn.send(loggedinMsg.encode())

    # add user to Dict of clients - key is username, value is connection
    with lock:
        clients[username] = clientConn

    # broadcast to all clients that user has joined
    joinmsg = "Login Message-" + username + " has joined the chat\n"
    msg_all_but_messenger(username, joinmsg)

    #Send MOTD
    motd(clientConn)

    #Catch up on messages
    catchup_messages(username)

    connected = True
    try:
        while connected:
            #get input from client, handle commands
            msg = getLine(clientConn).strip('\n')
            print(msg)

            if not msg.startswith("/"):
                #broadcast message to all clients
                broadcastmsg = username + ": " + msg + "\n"
                broadcast(broadcastmsg)

            # if command starts with "/" then it is a command
            # that will call a function
            else:
                if ' ' in msg:
                    command, rest = msg.split(' ', 1)
                    command = command.lstrip('/')
                else:
                    command = msg.lstrip('/')
                    rest = None

                if command == "who": who(clientConn)
                if command == "exit":
                    exit(clientConn, username)
                    connected = False
                if command == "tell":
                    if rest:
                        destUser, message = rest.split(' ', 1)
                        tell(username, destUser, message)
                if command == "motd": motd(clientConn)
                if command == "me":
                    print ("here")
                    me(username, rest)
                if command == "help": help(clientConn)

    except ConnectionResetError:
        print("Client Disconnected")
        pass

# Initial socket setup
serverPort = 12345
serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSock.bind( ('', serverPort) )
serverSock.listen(16)

print("Client running...")
print("Listening on port:", serverPort)

try:
    while True:
        #make a client connects - send to handleclient
        threading.Thread(target=handleClient, args=(*serverSock.accept(),), daemon=True).start()
except KeyboardInterrupt:
    print("\n Server Shutting down...")
    serverSock.close()

