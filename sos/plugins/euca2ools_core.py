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


class euca2ools_core(Plugin, RedHatPlugin):

    """euca2ools core commands:
    - euctl, including dumps of:
      - cloud.network.network_configuration
      - authentication.ldap_integration_configuration
    - euserv-*
    - euca-version
    - esi-describe-images
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def get_instance_statuses(self):
        """
        Grab the status of the instances on the cloud
        """
        get_instanceslist_cmd = ["euca-describe-instances",
                                 "verbose"]

        try:
            ilist, v = subprocess.Popen(get_instanceslist_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error obtaining list of Compute instances.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        for inst_info in ilist.splitlines():
            if re.search('INSTANCE', inst_info):
                inst_id = inst_info.split()[1]
                self.add_cmd_output("euca-describe-instance-status " + inst_id)

    def eucalyptus_core(self):
        self.add_cmd_output([
            "euca-version",
            "euca-describe-components",
            "euca-describe-nodes",
            "euca-describe-properties",
            "euca-describe-services --all -E",
            "euca-describe-storage-controllers",
            "euca-describe-cloudwatch",
            "euca-describe-compute",
            "euca-describe-euare",
            "euca-describe-loadbalancing",
            "euca-describe-object-storage-gateways",
            "euca-describe-tokens",
            "euca-describe-walrusbackends",
            "euctl -A",
            "euctl"
            + " --dump cloud.network.network_configuration"
            + " --format json",
            "euctl"
            + " --dump cloud.network.network_configuration"
            + " --format yaml",
            "euctl"
            + " --dump authentication.ldap_integration_configuration"
            + " --format json",
            "euctl"
            + " --dump authentication.ldap_integration_configuration"
            + " --format yaml",
            "euctl"
            + " --dump region.region_configuration"
            + " --format json",
            "euctl"
            + " --dump region.region_configuration"
            + " --format yaml",
            "euctl"
            + " -U http://localhost:8773/services/Properties"
            + " euca='com.eucalyptus.auth.principal.UserFullName.userIdMap"
            + ".asMap().entrySet()"
            + ".findAll{ entry -> entry.key != entry.value.userId }'",
            "euserv-describe-services --group-by-type",
            "euserv-describe-services --group-by-zone",
            "euserv-describe-services --group-by-host",
            "euserv-describe-services --expert",
            "euserv-describe-node-controllers",
            "euserv-describe-service-types",
            "euserv-describe-events",
            "esi-describe-images",
            "esi-manage-stack -a check imaging",
            "esi-manage-stack -a check database"
        ])

    def eucalyptus_ec2(self):
        self.add_cmd_output([
            "euca-describe-addresses verbose",
            "euca-describe-availability-zones verbose",
            "euca-describe-instance-types"
            + " --show-capacity --by-zone",
            "euca-describe-groups verbose",
            "euca-describe-images --all",
            "euca-describe-regions",
            "euca-describe-instances verbose",
            "euca-describe-keypairs verbose",
            "euca-describe-volumes verbose",
            "euca-describe-tags",
            "euca-describe-conversion-tasks verbose",
            "euca-describe-vpcs verbose",
            "euca-describe-network-acls verbose",
            "euca-describe-route-tables verbose",
            "euca-describe-subnets verbose",
            "euca-describe-snapshots verbose",
            "euca-describe-account-attributes",
            "euca-describe-customer-gateways",
            "euca-describe-dhcp-options",
            "euca-describe-internet-gateways",
            "euca-describe-network-interfaces",
            "euca-describe-vpc-peering-connections",
            "euca-describe-vpn-connections",
            "euca-describe-vpn-gateways"
        ])

        self.get_instance_statuses()

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Updating environment variables ###")
            os_env = euca_common.update_env()
            os.environ = os_env

            self.add_alert("### Grab Eucalyptus Core Service Information ###")
            self.eucalyptus_core()

            self.add_alert("### Grab Eucalyptus EC2 Information ###")
            self.eucalyptus_ec2()
        return
