import pwncat
from pwncat.modules import Status, BaseModule, ModuleFailed
from pwncat.modules.peas import PeassModule


class Module(BaseModule):

    PLATFORM = None

    def run(self, session: "pwncat.manager.Session"):

        modules = ["*"]
        module_names = modules

        modules = set()
        for name in module_names:
            modules = modules | set(
                list(session.find_module(f"peas.{name}", base=PeassModule))
            )

        for module in modules:

            try:
                module.run(session)
            except ModuleFailed as exc:
                session.log(f"[red]{module.name}[/red]: {str(exc)}")

        yield Status(session)
