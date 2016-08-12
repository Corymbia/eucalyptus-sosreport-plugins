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


class euca2ools_euscale(Plugin, RedHatPlugin):

    """euca2ools euscale commands:
    - all euscale-* commands
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def eucalyptus_autoscaling(self):
        self.add_cmd_output([
            "euscale-describe-auto-scaling-instances verbose --show-long",
            "euscale-describe-auto-scaling-groups verbose --show-long",
            "euscale-describe-launch-configs verbose --show-long",
            "euscale-describe-notification-configurations verbose",
            "euscale-describe-policies verbose --show-long",
            "euscale-describe-scaling-activities verbose --show-long",
            "euscale-describe-scheduled-actions verbose --show-long",
            "euscale-describe-termination-policy-types"
            ])

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Adding eucalyptus/admin credentials to environment ###")
            os_env = euca_common.update_env()
            os.environ = os_env

            self.add_alert("### Grab AutoScaling Service Information ###")
            self.eucalyptus_autoscaling()
        return
