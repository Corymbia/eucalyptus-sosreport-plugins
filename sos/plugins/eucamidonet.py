# Copyright (C) 2013 Eucalyptus Systems, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os

from sos.plugins import Plugin, RedHatPlugin


class eucamidonet(Plugin, RedHatPlugin):
    """MidoNet commands for Eucalyptus VPC
    """

    def update_env(self):
        # let's set a strict PATH for easy/trusted cmd access
        os_path = "/sbin:/bin:/usr/sbin:/usr/bin"
        os.environ['PATH'] = os_path

        # finally, share back the env var changes to the env
        os_env = os.environ.copy()
        return os_env

    # TODO: add some stuff specific to MidoNet
    def checkenabled(self):
        if (
            self.is_installed("python-midonetclient") and
            self.is_installed("midolman") and
            self.is_installed("midonet-api")
        ):
            return True
        return False

    def mido_copy_files(self):
        self.add_copy_spec("/etc/midolman")
        self.add_copy_spec("/etc/midonet_host_id.properties")
        self.add_copy_spec("/etc/init/midolman.conf")
        self.add_copy_spec("/etc/tomcat")
        self.add_copy_spec("/etc/zookeeper")
        self.add_copy_spec("/usr/etc/zookeeper")
        return

    def midonet_basics(self):
        self.add_cmd_output([
            "midonet-cli -e 'list router'",
            "midonet-cli -e 'list host'",
            "midonet-cli -e 'list bridge'",
            "midonet-cli -e 'list port-group'",
            "midonet-cli -e 'list chain'",
            "midonet-cli -e 'list tunnel-zone'",
            "mn-conf dump -s"
            ])

    def quagga_info(self):
        self.add_cmd_output([
            "vtysh -c 'show ip bgp summary'",
            "vtysh -c 'show ip bgp'"
        ])

    def setup(self):
        # if self.checkenabled():
            os_env = self.update_env()
            os.environ = os_env

            self.mido_copy_files()
            self.midonet_basics()
            self.quagga_info()

        # return
