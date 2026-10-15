import os

def ping_host(user_input):
    os.system("ping -c 1 " + user_input)
    return "Ping sent"