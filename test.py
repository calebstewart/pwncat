#!./env/bin/python
import pwncat.manager
import time

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Establish a session
session = manager.create_session("windows", host="192.168.122.11", port=4444)

session.platform.channel.send(
    b"""
csharp
/* ENDASM */
class command {
  public void main()
  {
    System.Console.WriteLine("We can execute C# Now!");
  }
}
/* ENDBLOCK */
powershell
Write-Host "And we can execute powershell!"
# ENDBLOCK
"""
)

manager.interactive()
