import time
from socket import *
import threading
#Server

#List of tuples containing client username and connection info
clients = []

# Admin user and list of banned users
admin = None
banned = []

#File containing users and the thread lock
user_file = "users.txt"
lock = threading.Lock()

#Dict of blocked IPs
#key is IP, value is timestamp
blockedIPs = {}

#Dict of timestamps for failed login attempts
#key is IP, value is list of timestamps
failedLogins = {}

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
    with lock:
        if username in [client[0] for client in clients]:
            return False, True

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
    with lock:
        for clientConn in [client[1] for client in clients]:
            clientConn.send(message.encode())

def msg_all_but_messenger(username, message):
    with lock:
        for user, client in clients:
            if user != username:
                client.send(message.encode())

def catchup_messages(username):
    with lock:
        if username in messages:
            msg = "You have private messages:\n"
            for client in clients:
                if username == client[0]:
                    conn = client[1]
            conn.send(msg.encode())
            for message in messages[username]:
                conn.send(message.encode())
            messages.pop(username)

def check_blocked(conn, userIP):
    if userIP in blockedIPs:
        # get timestamp from blockedIPs
        timestamp = blockedIPs[userIP]

        # get curr time
        currTime = time.time()

        # if they have been blocked longer than 2 minutes,
        # remove them from the blocked list and return False
        if currTime - timestamp > 120:
            blockedIPs.pop(userIP)
            return False
        else:
            # if they have been blocked for less than 2 minutes,
            # tell them the remaining time and return True
            remainingTime = 120 - (currTime - timestamp)
            #format time
            minutes = int(remainingTime/60)
            seconds = int(remainingTime % 60)
            blockedMsg = f"You have been blocked for {minutes} minutes and {seconds} seconds\n"
            conn.send(blockedMsg.encode())
            time.sleep(0.1)
            return True

    return False

def who(clientConn):
    with lock:
        clientConn.send("Users logged in:\n".encode())
        for client in clients:
            user = client[0]
            clientConn.send(f"{user}\n".encode())

def exit(clientConn, username):
    global admin
    with lock:
        clients.remove( (username, clientConn) )

        if admin == username:
            if clients:
                admin = clients[0][0]
            else:
                admin = None

    print(f"Disconnected from {username}")
    clientConn.close()
    return

def tell(srcUser, destUser, message):
    message = f"{srcUser} tells you: {message}\n"

    with lock:
        for client in clients:
            if destUser == client[0]:
                client[1].send(message.encode())
                return

    #check all registered users
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

def kick(username):
    conn = None
    with lock:
        for client in clients:
            if username == client[0]:
                conn = client[1]
                break
    if conn:
        exit(conn, username)

def ban(username):
    if username not in banned:
        kick(username)
        banned.append(username)

def unban(username):
    if username in banned:
        banned.remove(username)

def login(conn):
    print("Logging in...")

    #Send a message telling the client to enter username
    usermsg = "Enter your username:\n"
    username = ''
    while not username:
        conn.send(usermsg.encode())
        username = getLine(conn).strip('\n')

    #If user is banned, bail early
    if username in banned:
        return False, None

    #send a message telling the client to enter password
    passmsg = "Enter your password:\n"
    password = ''
    while not password:
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
    global admin
    print("Client Connected")
    #login protocol

    #if a user gets 3 failed attempts within 30 seconds, they get timed out
    attempts = 0

    while True:

        #if user is blocked, disconnect them
        blocked = check_blocked(clientConn, peerAddr[0])
        if blocked:
            print("Client is blocked")
            clientConn.close()
            return

        #if user is not blocked, continue with login protocol
        loginResult, username = login(clientConn)

        if username == None:
            bannedmsg = "This user has been banned.\n"
            clientConn.send(bannedmsg.encode())
            clientConn.close()
            return

        if loginResult:
            #remove user from failedLogins
            if peerAddr[0] in failedLogins:
                failedLogins.pop(peerAddr[0])
            break

        attempts += 1
        #take timestamp of attempt, append each attempt to list of failed logins
        print(f"Failed login attempt {attempts} for {peerAddr[0]}")
        if peerAddr[0] not in failedLogins:
            failedLogins[peerAddr[0]] = [time.time()]
        else:
            failedLogins[peerAddr[0]].append(time.time())

        #if attempts is greater than 3, check this timestamp against the
        #timestamp 2 attempts ago to see if they were within 30 seconds
        #if they were, block the user
        if attempts > 2:
            if failedLogins[peerAddr[0]][-1] - failedLogins[peerAddr[0]][-3] < 30:
                print("Blocking client")
                blockedIPs[peerAddr[0]] = time.time()

                #send message to client
                blockedMsg = "You have been blocked for 2 minutes\n"
                clientConn.send(blockedMsg.encode())

                #remove user from failedLogins
                failedLogins.pop(peerAddr[0])

                clientConn.close()
                return

    print("Client logged in successfully")
    loggedinMsg = "Logged in\n"
    clientConn.send(loggedinMsg.encode())

    # add user to list of clients - tuple of username and connection
    with lock:
        clients.append( (username,clientConn) )

    if not admin:
        admin = username

    # broadcast to all clients that user has joined
    joinmsg = "Login Message-" + username + " has joined the chat\n"
    msg_all_but_messenger(username, joinmsg)

    #Send MOTD
    motd(clientConn)

    #Catch up on messages
    catchup_messages(username)

    try:
        # While the client is connected
        while clientConn.fileno() != -1:
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
                    rest = ""

                if command == "who": who(clientConn)
                elif command == "exit": exit(clientConn, username)
                elif command == "tell":
                    if rest:
                        destUser, message = rest.split(' ', 1)
                        tell(username, destUser, message)
                elif command == "motd": motd(clientConn)
                elif command == "me": me(username, rest)
                elif command == "help": help(clientConn)

                # Admin Commands
                elif admin == username and command == "kick":
                    if rest: kick(rest)
                elif admin == username and command == "ban":
                    if rest: ban(rest)
                elif admin == username and command == "unban":
                    if rest: unban(rest)

                else:
                    broadcastmsg = username + ": /" + command + rest + "\n"
                    broadcast(broadcastmsg)


    except ConnectionResetError:
        print("Client Disconnected")
    except BrokenPipeError:
        print("Client forcibly disconnected")
    finally:
        exit(clientConn, username)

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

