from socket import *
import threading
import sys
from time import sleep
import curses

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
def listen(conn, display_win, input_win):
    while not stop_event.is_set():
        msg = getLine(conn)
        if not msg:
            stop_event.set()
            serverSock.close()
        if msg == "Enter your username:\n" or msg == "Enter your password:\n":
            input_win.addstr(0, 0, msg)
            input_win.refresh()
            continue
        display_win.addstr(msg)
        display_win.refresh()

#connect to server - login protocol
def handle_user_input(conn, input_win, screen):
    user_input = ""
    while conn.fileno() != -1:
        input_win.addstr(1, 0, "> " + user_input)
        input_win.refresh()

        key = screen.getch()

        if key == curses.KEY_BACKSPACE:
            user_input = user_input[:-1]
            input_win.clear()
        elif key == curses.KEY_ENTER or key == 10:
            user_input = user_input + '\n'
            try:
                conn.send( user_input.encode() )
            except ConnectionResetError:
                stop_event.set()
                sleep(0.1)
                serverSock.close()
                print("Server Disconnected")

            if user_input == "/exit\n":
                stop_event.set()
                sleep(0.1)
                serverSock.close()
                return

            user_input = ""
            input_win.clear()
        elif key >= 32 and key <= 126:
            user_input += chr(key)

def interface(screen):
    curses.curs_set(1)
    screen.clear()
    screen.refresh()

    height,width = screen.getmaxyx()

    input_height = 3
    chat_log_height = height - input_height - 1
    
    chat_log_win = curses.newwin(chat_log_height, width, 0, 0)
    chat_log_win.scrollok(True)

    border_win = curses.newwin(1, width, chat_log_height, 0)
    border_win.addstr(0, 0, "-"*(width-1))
    border_win.refresh()

    input_win = curses.newwin(input_height, width, chat_log_height+2, 0)

    try:
        serverSock.connect( (serverIP, serverPort) )
        #make thread for incoming messages
        threading.Thread(target=listen, args=(serverSock, chat_log_win, input_win), daemon=True).start()

        handle_user_input(serverSock, input_win, screen)

    except KeyboardInterrupt:
        print("Client Shutting Down...")
        stop_event.set()
        serverSock.close()
    except Exception as e:
        print("Server disconnected. Shutting down...")

try:
    curses.wrapper(interface)
except Exception as e:
    print(f"Error: {e}")
