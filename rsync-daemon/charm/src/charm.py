#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.

import ops
import json
import pathlib
import subprocess
from ops.model import ActiveStatus

from charmlibs.seceng import utils
from charmlibs.seceng.base import Snap, Package, SecEngCharmBase
from charmlibs.seceng.interfaces import RsyncRelationUnitData

def _safe_json_decoder(val):
    """ Custom decoder to handle Juju's auto-injected network data """

    try:
        return json.loads(val)
    except json.JSONDecodeError:
        # Catch and return the raw string for extra fields added by Juju, e.g.: private-address, ingress-address, egress-subnets
        return val


class RsyncDaemonCharm(SecEngCharmBase):
    """ Charm the service """

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.secret_changed, self._on_secret_changed)
        framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.stop, self._on_stop)

        framework.observe(self.on.rsync_module_relation_changed, self._on_relation_changed)
        framework.observe(self.on.rsync_module_relation_broken, self._on_relation_broken)

    def _setup_rsync(self):
        """ Install rsync and setup the base configuration """
        self.unit.status = ops.MaintenanceStatus("Installing rsync")

        subprocess.check_call(['apt-get', 'update'])
        subprocess.check_call(['apt-get', 'install', '-y', 'rsync'])

        # Write the global rsync config
        with utils.open_file_secure(pathlib.Path('/etc/rsyncd.conf'), mode=0o644, text=True) as file:
            file.write("""uid = nobody
gid = nogroup
use chroot = yes
max connections = 20
syslog facility = local5
pid file = /run/rsyncd.pid
&include /etc/rsyncd.conf.d/
""")
        pathlib.Path('/etc/rsyncd.conf.d').mkdir(exist_ok=True)

        self.unit.status = ops.ActiveStatus("rsync daemon running")

    def _on_relation_changed(self, event: ops.RelationChangedEvent):
        """ Read data from the principal charm and configure the module """
        remote_unit = event.unit

        if not remote_unit:
            return

        # Fetch the data provided by nvd-sync
        data = event.relation.load(RsyncRelationUnitData, remote_unit, decoder=_safe_json_decoder)

        # Ensure the principal charm has populated the data before proceeding
        # FIXME: move validation to pydantic model
        if not data.path or not data.module:
            return

        self.unit.status = ops.MaintenanceStatus(f"Configuring [{data.module}] module")

        # Write the drop-in configuration
        conf_content = f"""[{data.module}]
    path = {data.path}
    comment = {data.comment}
    read only = {"yes" if data.read_only else "no"}
    list = yes
"""
        # Using the relation id for the conf filename to allow for proper cleanup when a relation is broken
        with utils.open_file_secure(
            pathlib.Path(f'/etc/rsyncd.conf.d/relation-{event.relation.id}.conf'),
            mode=0o644,
            text=True
        ) as conf_file:
            conf_file.write(conf_content)

        # Restart to apply changes
        subprocess.check_call(['systemctl', 'restart', 'rsync'])
        self.unit.status = ops.ActiveStatus(f"Serving module [{data.module}]")

    def _on_relation_broken(self, event: ops.RelationBrokenEvent):
        """ Clean up a relation's config when removed """
        conf_file = pathlib.Path(f'/etc/rsyncd.conf.d/relation-{event.relation.id}.conf')

        if conf_file.exists():
            conf_file.unlink()
            subprocess.check_call(['systemctl', 'restart', 'rsync'])

        self.unit.status = ops.ActiveStatus("rsync daemon running")

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        self._setup_rsync()
        self.unit.status = ActiveStatus('ready (config)')

    def _on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        self.unit.status = ActiveStatus('ready (secret)')

    def _on_upgrade_charm(self, event: ops.UpgradeCharmEvent) -> None:
        self.unit.status = ActiveStatus('ready (upgrade)')

    def _on_start(self, event: ops.StartEvent) -> None:
        subprocess.check_call(['systemctl', 'enable', 'rsync'])
        subprocess.check_call(['systemctl', 'start', 'rsync'])

    def _on_stop(self, event: ops.StopEvent) -> None:
        subprocess.check_call(['systemctl', 'stop', 'rsync'])
        subprocess.check_call(['systemctl', 'disable', 'rsync'])

if __name__ == "__main__":  # pragma: nocover
    ops.main(RsyncDaemonCharm)
