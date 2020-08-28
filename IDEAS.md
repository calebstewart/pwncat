# Feature and Changes Ideas

I'm just rambling some ideas I have here.

## C2 Channels

I think it could be helpful to establish an abstract C2 channel class 
to allow pwncat to communicate over different C2 methods. For example,
`Bind` and `Reverse` channel classes could handle the standard bind and
reverse methods. An `SSH` channel could handle SSH connections.

There is also potential for numerous other methods such as DNS, ICMP,
etc. A Channel class would look a lot like a socket, but would guarantee
a consistent interface across C2 types.

## Module access

Modules are currently segmented by type. There are persistence, privilege
escalation, and enumeration modules. These modules are all implemented 
independently and accessed through separate commands. 

This is helpful for segmenting the different parts of pwncat into different
base goals, but hinders the ease of development for new modules. This
interface does not provide a simple way for complex modules to accept
parameters and forces the developer to remember the interface for all of 
these different command frameworks.

I was initially hesitant to adopt the Metasploit Framework way of doing
things where every action was a module, because I wanted to keep things
simpler, but as the framework grows and more complex modules are
implemented, I think this is needed, but needs to be implemented in such
a way that the modules can be interfaced with programmatically as well.

I'm thinking of something like this from a programmatic standpoint:

```python
# Attempt all privileg escalation modules
for module in pwncat.modules.match(r"escalate/.*"):
    try:
        module.run(target=user)
        break
    except PrivescError:
        pass

# Collect facts from all enumeration modules
facts = []
for module in pwncat.modules.match(r"enumerate/.*"):
    facts.extend(module.run())

# Install persistence
pwncat.modules.match(r"persist/.*").run(
    user = "root",
    lhost = "10.0.0.1",
    lport = "4444",
)
```

A module may look something like this:

```python
class Module(BaseModule):
    
    ARGUMENTS = {
        "user": { "type": str, "default": None },
        "lhost": { "type": ipaddress.ip_address },
        "lport": { "type": int, "default": 4444 }
    }
    
    def run(self, user, lhost, lport):
        """ Install this persistence method """
        return
```

From a REPL point of view, it would look a lot like metasploit. You can
`use` a module. After using a module, any `set` actions would set 
configurations for this specific module. If you do not have a module 
loaded, then using `set` will set the configuration globally. If a 
configuration is not set locally when `run` is executed, then the global
configuration will be checked for matching arguments for the module.

```sh
# Install a persistence mthod with a bind channel
use persistence/system/cron
set method channels/bind
set schedule "* * */1 *"
set lhost 10.0.0.1
set lport 4444
run

# Same as above
run persistence/system/cron method=channels/bind lhost=10.0.0.1 lport=4444

# Set a global configuration, applies to all modules
set -g lhost 10.0.0.1
```

The above programmatic interface could be used to implement the same 
automated escalation features we had before.

```python
attempted_modules = []
attempted_users = []
for module in pwncat.modules.match("escalate/.*"):
    if module in attempted_modules:
        continue
    try:
        module.run(
            user=target_user,
            ignore_users=attempted_users,
            ignore_modules=[m.name for m in attempted_modules]
        )
    except PrivescFailed as exc:
        attempted_modules.extend(exc.attempted_modules)
        attempted_users.extend(exc.attempted_users)
```

The `escalate` modules would be created separately from others. They
would inherit from a `EscalationModule` class, which provides a
standard interface to the `run` method. The subclasses would be 
responsible for similar `enumerate`, `escalate`, `write` and `read`
methods that are currently implemented. 

This allows an individual privilege escalation method to be run
like this:

```sh
run escalate/sudo user=admin
```

While the standard automated privilege escalation can be accomplished
with a simple:

```sh
use escalate
set user admin
set ignore_module ["sudo"]
run

# Or completely automated for root
run escalate
```

Enumerate possibly valid escalation methods

```sh
# List possibly valid escalation methods to user admin
run escalate/list user=admin
# List possibly valid escalation methods, ignoring the given modules
run escalate/list ignore_module=["sudo"]
```
