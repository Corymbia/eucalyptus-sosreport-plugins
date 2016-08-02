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


class euca2ools_euwatch(Plugin, RedHatPlugin):

    """euca2ools CloudWatch commands:
    - all euwatch commands
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def update_env(self):
        os.environ['AWS_DEFAULT_REGION'] = 'admin@localhost'

        # let's also set a strict PATH for easy/trusted cmd access
        os_path = "/sbin:/bin:/usr/sbin:/usr/bin"
        os.environ['PATH'] = os_path

        os_env = os.environ.copy()
        return os_env

    def eucalyptus_cloudwatch(self):
        self.add_cmd_output([
            "euwatch-describe-alarms verbose --show-long",
            "euwatch-describe-alarm-history verbose --show-long",
            "euwatch-list-metrics"
            ])

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Adding eucalyptus/admin credentials to environment ###")
            os_env = self.update_env()
            os.environ = os_env

            self.add_alert("### Grab CloudWatch Service Information ###")
            self.eucalyptus_cloudwatch()
        return
