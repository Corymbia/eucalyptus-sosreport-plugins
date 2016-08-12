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
import subprocess
import re
import euca_common


class euca2ools_euform(Plugin, RedHatPlugin):

    """euca2ools cloudformation commands:
    - all euform-* commands
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def get_stacks(self):
        """
        Grab the Cloudformation Stacks
        """
        get_stacklist_cmd = ["euform-describe-stacks",
                             "verbose",
                             "--show-long"]

        try:
            slist, v = subprocess.Popen(get_stacklist_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error obtaining Cloudformation Stacks.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        stacks = []
        for stack_info in slist.splitlines():
            if re.search('^arn:', stack_info):
                stack_id = "".join(stack_info.split())
                stacks.append(stack_id)
        return stacks

    def get_cloudformation_resources(self, stack):
        """
        Grab the resources of Cloudformation stack
        """
        sColon = re.compile('[:]')
        entry = sColon.split(stack)
        stack_name = entry[5].strip().split("/")[1]
        stack_id = entry[5].strip().split("/")[2]

        self.add_cmd_output("euform-list-stack-resources "
                            + stack,
                            suggest_filename="euform-list-stack-resources-"
                            + stack_name
                            + "-" + stack_id)
        self.add_cmd_output("euform-describe-stack-resources "
                            + "-n " + stack,
                            suggest_filename="euform-describe-stack-resources-"
                            + stack_name
                            + "-" + stack_id)
        self.add_cmd_output("euform-describe-stack-events "
                            + stack,
                            suggest_filename="euform-describe-stack-events-"
                            + stack_name
                            + "-" + stack_id)

    def eucalyptus_cloudformation(self):
        self.add_cmd_output("euform-describe-stacks verbose --show-long")
        for stack in self.get_stacks():
            self.get_cloudformation_resources(stack)

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Adding eucalyptus/admin credentials to environment ###")
            os_env = euca_common.update_env()
            os.environ = os_env

            self.add_alert("### Grab CloudFormation Service Information ###")
            self.eucalyptus_cloudformation()
        return
