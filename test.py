#!./env/bin/python
import pwncat.manager

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Establish a session
session = manager.create_session("windows", host="192.168.122.11", port=4444)

manager.interactive()
