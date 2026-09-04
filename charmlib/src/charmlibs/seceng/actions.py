

class Action(abc.ABC):
    @abc.abstractmethod
    def execute(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def __eq__(self, other: typing.Any) -> bool:
        # Subclasses of Action must implement __eq__ and __hash__ so that they
        # can be compared to each other to allow duplicates to be removed.
        raise NotImplementedError

    @abc.abstractmethod
    def __hash__(self) -> int:
        raise NotImplementedError

    @staticmethod
    def parse(action: str) -> Action:
        if action.startswith('dpkg-reconfigure:'):
            package = action.split(':', 1)[1]
            return DpkgReconfigureAction(package)
        elif action == 'systemctl:daemon-reload':
            return SystemctlDaemonReloadAction()
        elif action.startswith('systemctl:enable:'):
            return SystemctlEnableAction(action.split(':', 2)[2])
        elif action.startswith('systemctl:restart:'):
            return SystemctlRestartAction(action.split(':', 2)[2])
        else:
            raise ValueError(f"unsupported action '{action}'")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: typing.Any, handler: pydantic.GetCoreSchemaHandler
    ) -> pydantic_core.CoreSchema:
        return pydantic_core.core_schema.no_info_after_validator_function(cls.parse, handler(str))


class ActionQueue(deque[Action]):
    def update_actions(self, new_actions: collections.abc.Iterable[Action]) -> None:
        # This function updates actions (in the outer scope) to add the
        # entries in new_actions, but without duplicating entries in
        # actions unless necessary. The order of items in actions is not
        # changed and nor is the order of items in new_actions. However,
        # new items can be interleaved. If actions already contains an
        # identical (compared with ==) item, a new one is not added, unless
        # the previously mentioned constraints cannot be kept.
        # Example:
        #  - actions is: A, B, C, A
        #  - new_actions is: C, B, A
        #  - result is: A, B, C, B, A
        search_index = 0
        for action in new_actions:
            try:
                search_index = self.index(action, search_index) + 1
            except ValueError:
                self.insert(search_index, action)
                search_index += 1


class DpkgReconfigureAction(Action):
    def __init__(self, package: str):
        if not package:
            raise ValueError("package must not be empty")
        self.package = package

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, DpkgReconfigureAction):
            return False
        return self.package == other.package

    def __hash__(self) -> int:
        return hash(self.package)

    def execute(self) -> None:
        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if os.geteuid() == 0:
            logging.info(f"About to reconfigure package '{self.package}'.")
            subprocess.check_call(['dpkg-reconfigure', '-fnoninteractive', self.package])
        else:
            logging.warning(f"Skipping reconfigure of package '{self.package}' because we're not running as root.")


class SystemctlDaemonReloadAction(Action):
    def __eq__(self, other: typing.Any) -> bool:
        return type(other) is type(self)

    def __hash__(self) -> int:
        return hash(type(self))

    def execute(self) -> None:
        # FIXME: euid check is for tests. Tests should however provide mock commands, instead.
        if os.geteuid() == 0:
            logging.info("About to reload systemd daemon.")
            subprocess.check_call(['systemctl', 'daemon-reload'])
        else:
            logging.warning("Skipping reloading of systemd daemon because we're not running as root.")


class SystemctlEnableAction(Action):
    """Enable a systemd service after its unit file was written.

    Paired with the unit-file entry because a first-install charm hook would
    enable a unit file that does not exist yet. The action is idempotent.
    """

    def __init__(self, service: str):
        if not service:
            raise ValueError("service must not be empty")
        self.service = service

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, SystemctlEnableAction):
            return False
        return self.service == other.service

    def __hash__(self) -> int:
        return hash(self.service)

    def execute(self) -> None:
        if os.geteuid() == 0:
            logging.info(f"About to enable service '{self.service}'.")
            subprocess.check_call(['systemctl', 'enable', self.service])
        else:
            logging.warning(f"Skipping enable of service '{self.service}' because we're not running as root.")


class SystemctlRestartAction(Action):
    """Restart a systemd service after a templated file it depends on changed.

    The restart is attached to the file, so it fires when the file's inputs
    change. It is input-driven rather than output-driven: even identical
    rendered bytes still restart the service. A template that must follow a
    versioned artifact therefore has to read something that changes with it,
    such as ``installed[...]``.
    """

    def __init__(self, service: str):
        if not service:
            raise ValueError("service must not be empty")
        self.service = service

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, SystemctlRestartAction):
            return False
        return self.service == other.service

    def __hash__(self) -> int:
        return hash(self.service)

    def execute(self) -> None:
        if os.geteuid() == 0:
            logging.info(f"About to restart service '{self.service}'.")
            subprocess.check_call(['systemctl', 'restart', self.service])
        else:
            logging.warning(f"Skipping restart of service '{self.service}' because we're not running as root.")

