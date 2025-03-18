from socket import *
import threading
import sys
from time import sleep

#Client
serverIP = sys.argv[1]
serverPort = int(sys.argv[2])

serverSock = socket(AF_INET, SOCK_STREAM)

# Event that allows listening thread to be stopped early
stop_event = threading.Event()

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

#separate thread handling incoming messages
def listen(conn):
    while not stop_event.is_set():
        msg = getLine(conn).strip('\n')
        if not msg:
            stop_event.set()
            serverSock.close()
        print(msg, flush=True)

#connect to server - login protocol

try:
    serverSock.connect( (serverIP, serverPort) )
    #make thread for incoming messages
    threading.Thread(target=listen, args=(serverSock, ), daemon=True).start()

    while True:
        #get input from user, send to server
        sleep(0.1)

        # When still connected to the server, ask for a command
        if serverSock.fileno() != -1:
            command = input("> ") + '\n'

        try:
            serverSock.send( command.encode() )
        except ConnectionResetError:
            print("Server Disconnected")

        #until /quit from user or keyboard interrupt
        if command.strip('\n') == "/exit":
            stop_event.set()
            sleep(0.1)
            serverSock.close()
            break

except KeyboardInterrupt:
    print("Client Shutting Down...")
    stop_event.set()
    serverSock.close()
except Exception as e:
    print("Server disconnected. Shutting down...")
