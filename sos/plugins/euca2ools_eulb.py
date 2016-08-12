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

from sos.plugins import Plugin, RedHatPlugin
import os
import os.path
import euca_common


class euca2ools_eulb(Plugin, RedHatPlugin):

    """euca2ools eulb commands:
    - all eulb-* commands
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def eucalyptus_elb(self):
        self.add_cmd_output([
            "eulb-describe-lb-policies --show-long",
            "eulb-describe-lb-policy-types --show-long",
            "eulb-describe-lbs --show-long"
            ])

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Adding eucalyptus/admin credentials to environment ###")
            os_env = euca_common.update_env()
            os.environ = os_env

            self.add_alert("### Grab Load Balancing Service Information ###")
            self.eucalyptus_elb()
        return
