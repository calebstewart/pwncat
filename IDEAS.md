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

```python

class Channel:

    PLATFORM = Platform.UNKNOWN
    
    def recv(self, count: Optional[int] = None):
        raise NotImplementedError
    
    def send(self, data: bytes):
        raise NotImplementedError
        
    @classmethod
    def connect(cls, connection_string: str, port: int, platform: Platform) -> "Channel":
        """ Called by the connect command. May look like:
        # Connect via ssh
        connect ssh user@host
        connect ssh -p 2222 user@host
        # Connect via raw socket
        connect host 4444
        # Connect via bind socket
        connect bind -p 4444
        # Connect via other types
        connect icmp host
        # Connect for specific platform
        connect -P windows host 4444
        connect bind -P linux -p 4444
        
        Technically, the first positional parameter is the connection string
        and the second is the port number. You can also specify the port number
        with `-p` or `--port`. The positional syntax is more natural for raw
        socket connect channels, while the `-p` is more natural for ssh and
        bind sockets.
        """
        raise NotImplementedError

```

## Platform Abstraction

To facilitate true multi-platform functionality, some information should be abstracted
away from the platform. I think this would look like separating the victim object out
into a base class and sub-classes. The base class could be called `Platform` and take
over for the `Platform` Flags class we currently have. Instead of testing a flags class,
we could have `PLATFORM` in modules be an array of supported platform classes, and use
a similar syntax where it would look like `type(pwncat.victim) in module.PLATFORM` or
`isinstance(pwncat.victim, platform.Linux)`.

```python
class Platform:
    
    def __init__(self, channel: Channel):
        # Save the channel for future use
        self.channel = channel
        
        # Set the prompt
        self.update_prompt()
        
        # Spawn a pty if we don't have one
        if not self.has_pty():
            self.spawn_pty()
            
    def has_pty(self) -> bool:
        """ Check if the current shell has a PTY """
        
    def spawn_pty(self):
        """ Spawn a PTY in the current shell for full interactive features """
        
    def update_prompt(self):
        """ Set the prompt for the current shell """
    
    def which(self, name: str) -> str:
        """ Look up a binary on the remote host and return it's path """
    
    def cd(self, directory: str):
        """ Change directories """
        
    def listdir(self, directory: str = None) -> Generator[int, None, None]:
        """ Return a list of all items in the current directory """
        
    def cwd(self) -> str:
        """ Get the current working directory """
        
    def current_user(self) -> User:
        """ Get a user object representing the current user """
    
    def current_uid(self) -> int:
        """ Get the current user id. This is faster than querying the whole user object """
    
    def open(self, path: str, mode: str, content_length: int) -> Union[TextIO, BinaryIO]:
        """ Mimic built-in open function to open a remote file and return a stream. """
        
    def exec(self, argv: List[str], envp: List[str], stdout: str, stderr: str, stream: bool = False) -> Union[str, BinaryIO]:
        """ Execute a remote binary and return the stdout. If stream is true, return a
        file-like object where we can read the results. """
        
    def process(self, argv: List[str], envp: List[str], stdout: str, stderr: str) -> bytes:
        """ Execute a remote binary, but do not wait for completion. Return string which
        indicates the completion of the command """
        
class Linux(Platform):
    """ Implement the above abstract methods """ 
    
class Windows(Platform):
    """ Implement the above abstract methods """
```

With both channels and platforms implemented, the initialization would
look something like this:

```python

# Initialize scripting engine
script_parser = pwncat.commands.Parser()

# Run the connect command
try:
    script_parser.dispatch_line(shlex.join(["connect", *remaining_args]), command="pwncat")
except:
    # Connection failed
    exit(1)

# The connect command initialized the `pwncat.victim` object,
# but it doesn't have a parser yet. We already initialized one
# so store it there.
pwncat.victim.parser = script_parser
```

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

## Better Progress Handling

Currently, progress is handled in a syntactically interesting but possibly confusing way.
I utilize Python generators to yield the results of iterative modules. The generators
can also yield `Status` objects. These objects are filtered from the actual results of
generators and used to only update the progress bar. This allows modules to provide updates
without having to worry about the state or existence of a progress bar.

The problem is that if these modules call other methods or functions, passing this
capability on becomes problematic unless a `yield from` is used. The module wrapper currently
uses some python magic to check if a method returns a generator and yield/return
appropriately. I'd prefer to keep this kind of language-level code out of modules, so I'm
considering changing this design. A global (or rather, victim-level) progress bar can be
managed. Something like this:

```python
# Update the most recent task
pwncat.victim.progress.status("Here's a status update")
# Create a new task
task = pwncat.victim.progress.task("module or action", category="goal")
# Update a specific task
pwncat.victim.progress.status("Here's a status update", task=task)
```

The progress bar itself will be managed by the `Victim` object. We can keep the standard
now where iterative/generator based results are used to update a task, but also allows
modules to directly call `pwncat.victim.progres.status`. This would do away with the `Status`
class. Further, it allows the `module.run` method to return the raw result of the underlying 
method allowing more flexibility in the return values of modules. It allows modules to have 
asynchronous (generator) return values.

This in turn may allow intermediate results to be displayed by the `run` command. Currently,
the `run` command categorizes the results before displaying. It may be able to be adopted
to asynchronously print results as the module runs.
