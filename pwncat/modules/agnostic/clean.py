#!/usr/bin/env python3

from pwncat.modules import Status, Argument, BaseModule


class Module(BaseModule):
    """Clean up any modifications to the target. This mainly includes
    tampers saved in the database, but could include other changes added
    to future versions of pwncat."""

    PLATFORM = None

    def run(self, session: "pwncat.manager.Session"):
        """ Iterate over all tampers and revert what we can """

        current_user = session.current_user()

        for tamper in session.run("enumerate", types=["tamper"]):
            if not tamper.revertable:
                session.log(
                    f"[yellow]warning[/yellow]: {tamper.title(session)}: not revertable"
                )
                continue
            if current_user.id != tamper.uid:
                session.log(
                    f"[yellow]warning[/yellow]: {tamper.title(session)}: incorrect uid to rever"
                )
                continue

            try:
                # Attempt tamper revert
                yield Status(tamper.title(session))
                tamper.revert(session)
            except ModuleFailed as exc:
                session.log(f"[yellow]warning[/yellow]: {tamper.title(session)}: {exc}")

        session.db.transaction_manager.commit()
