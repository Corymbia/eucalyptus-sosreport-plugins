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
from sos.policies import PackageManager

from sos.plugins import Plugin, RedHatPlugin
import os
import os.path
import subprocess
import re


class eucafrontend(Plugin, RedHatPlugin):

    """Eucalyptus Cloud - Frontend
    """

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def checkversion(self, pkg):
        package_manager = PackageManager(
            'rpm -qa --queryformat "%{NAME}|%{VERSION}\\n"')
        all_euca_pkgs = package_manager.get_pkg_list()
        eucapkg = all_euca_pkgs.get(pkg)
        return '.'.join(eucapkg['version'])

    def clc_status(self):
        clc_check_cmd = ["/sbin/service", "eucalyptus-cloud", "status"]
        """
        Check for eucalyptus-cloud process
        """
        try:
            clc_check_output, unused_val = subprocess.Popen(
                clc_check_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error checking eucalyptus-cloud process")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)

        if re.match("^Eucalyptus services are running", clc_check_output):
            self.add_alert("Eucalyptus services are running")
            pass
        else:
            """
            Check eucalyptus-cloud process (in case error with /sbin/service)
            """
            clc_pgrep_cmd = ["/usr/bin/pgrep", "eucalyptus"]
            try:
                clc_pgrep_chk, unused_val = subprocess.Popen(
                    clc_pgrep_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()
            except OSError, e:
                error_string = '%s' % e
                if 'No such' in error_string:
                    self.add_alert("Error eucalyptus-cloud process status")
                    raise OSError(e)
                else:
                    self.add_alert("Error: %s" % e)
                    raise OSError(e)

            if clc_pgrep_chk:
                for proc in clc_pgrep_chk.splitlines():
                    if not proc:
                        raise
                    else:
                        self.add_alert("Eucalyptus services: " + proc + ".")
            else:
                self.add_alert("Error: eucalyptus-cloud process status")
                print "### eucalyptus-cloud process doesn't seem to be running"
                raise

    def euca2ools_conf_setup(self):
        """
        Create ini file under /etc/euca2ools/conf.d directory from
        information in admin/eucalyptus credentials file (eucarc)
        """

        ini_file = '/etc/euca2ools/conf.d/sosreport.ini'

        try:
            if not os.path.isdir("/etc/euca2ools/conf.d"):
                os.mkdir("/etc/euca2ools/conf.d")
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error creating "
                               + "/etc/euca2ools/conf.d directory")
                raise OSError(e)
            elif 'File exist' in error_string:
                self.add_alert("WARN: %s" % e)
                pass
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)

        # Let's set up a temporary euca2ools conf file - first make sure
        # there's no pre-existing file
        try:
            os.remove(ini_file)
        except OSError:
            pass

        euca2ools_conf = open(ini_file, 'w')

        euca_ini = "; sosreport (all user services on localhost)\n" \
            + "\n" \
            + "[region sosreport]\n" \
            + "autoscaling-url = http://127.0.0.1:8773/services/AutoScaling/\n" \
            + "cloudformation-url = http://127.0.0.1:8773/services/CloudFormation/\n" \
            + "ec2-url = http://127.0.0.1:8773/services/compute/\n" \
            + "elasticloadbalancing-url = http://127.0.0.1:8773/services/LoadBalancing/\n" \
            + "iam-url = http://127.0.0.1:8773/services/Euare/\n" \
            + "monitoring-url = http://127.0.0.1:8773/services/CloudWatch/\n" \
            + "s3-url = http://127.0.0.1:8773/services/objectstorage/\n" \
            + "sts-url = http://127.0.0.1:8773/services/Tokens/\n" \
            + "\n" \
            + "bootstrap-url = http://127.0.0.1:8773/services/Empyrean/\n" \
            + "properties-url = http://127.0.0.1:8773/services/Properties/\n" \
            + "reporting-url = http://127.0.0.1:8773/services/Reporting/\n" \
            + "\n" \
            + "certificate = /var/lib/eucalyptus/keys/cloud-cert.pem\n"

        euca2ools_conf.write(euca_ini)
        return ini_file

    def update_env(self):
        cmd = '/usr/sbin/clcadmin-assume-system-credentials'
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]

        # remove double quotes from strings, remove trailing semicolon
        p = re.sub('[;"]', '', p)

        cmd_l = p.splitlines()

        # remove blank lines
        cmd_l = filter(lambda x: len(x) > 0, cmd_l)

        env_add_l = filter(lambda x: x.split()[0] == 'export', cmd_l)
        env_remove_l = filter(lambda x: x.split()[0] == 'unset', cmd_l)

        # remove 'export'
        env_add_l = map(lambda x: x.split()[1], env_add_l)
        # remove 'unset'
        env_remove_l = map(lambda x: x.split()[1], env_remove_l)

        # set env vars
        for i in env_add_l:
            (env_var, env_str) = i.split('=')
            os.environ[env_var] = env_str

        # remove env vars not intended to be present
        for env_var in env_remove_l:
            if env_var in os.environ.keys():
                del os.environ[env_var]

        os.environ['AWS_DEFAULT_REGION'] = 'admin@sosreport'

        os_env = os.environ.copy()
        return os_env

    def get_accountlist(self):
        """
        Grab a listing of Euare accounts and return the list
        """

        get_actlist_cmd = ["/usr/bin/euare-accountlist", ]

        try:
            actlist, v = subprocess.Popen(get_actlist_cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error grabbing Euare Account List.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        accounts = []
        for account_info in actlist.splitlines():
            entry = re.split(r'\t', account_info)
            accounts.append(re.escape(entry[0]))
        return accounts

    def get_account_info(self, account):
        """
        Grab resources associated with the Euare account passed in
        """
        self.get_cmd_output_now("/usr/bin/euare-accountaliaslist "
                                + "--as-account "
                                + account,
                                suggest_filename="euare-accountaliaslist-"
                                + account)
        self.get_cmd_output_now("/usr/bin/euare-accountlistpolicies -a "
                                + account + " -v",
                                suggest_filename="euare-accountlistpolicies-"
                                + account)
        self.get_cmd_output_now("/usr/bin/euare-userlistbypath --as-account "
                                + account,
                                suggest_filename="euare-userlistbypath-"
                                + account)
        self.get_cmd_output_now("/usr/bin/euare-grouplistbypath "
                                + "--as-account "
                                + account,
                                suggest_filename="euare-grouplistbypath-"
                                + account)
        self.get_cmd_output_now("/usr/bin/euare-rolelistbypath "
                                + "--as-account "
                                + account,
                                suggest_filename="euare-rolelistbypath-"
                                + account)
        self.get_cmd_output_now("/usr/bin/euare-instanceprofilelistbypath "
                                + "--as-account "
                                + account,
                                suggest_filename="euare-instprflstbypath-"
                                + account)

    def get_userlist(self, account):
        """
        Grab list of users of the Euare account; return the list of users
        """
        get_userlist_cmd = ["/usr/bin/euare-userlistbypath",
                            "--as-account", account]

        try:
            usrlist, v = subprocess.Popen(get_userlist_cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error: " + account + " User List.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        users = []
        sColon = re.compile('[:]')
        for user_info in usrlist.splitlines():
            entry = sColon.split(user_info)
            user_id = entry[5].strip().split("/")
            users.append(user_id[1])
        return users

    def get_account_user_info(self, account, user):
        """
        Grab resources of users in the Euare account passed in
        """
        self.get_cmd_output_now("/usr/bin/euare-usergetinfo --as-account "
                                + account + " -u " + user,
                                suggest_filename="euare-usergetinfo-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-usergetloginprofile "
                                + "--as-account "
                                + account + " -u " + user,
                                suggest_filename="euare-usergetloginprofile-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-userlistcerts --as-account "
                                + account + " -u " + user,
                                suggest_filename="euare-userlistcerts-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-usergetattributes "
                                + "--as-account "
                                + account + " -u " + user
                                + " --show-extra",
                                suggest_filename="euare-usergetattributes-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-userlistgroups "
                                + "--as-account "
                                + account + " -u " + user,
                                suggest_filename="euare-userlistgroups-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-userlistkeys --as-account "
                                + account + " -u " + user,
                                suggest_filename="euare-userlistkeys-"
                                + account + "-" + user)
        self.get_cmd_output_now("/usr/bin/euare-userlistpolicies "
                                + "--as-account "
                                + account + " -u " + user
                                + " -v",
                                suggest_filename="euare-userlistpolicies-"
                                + account + "-" + user)

    def get_grouplist(self, account):
        """
        Grab the groups from the Euare account passed in and return the list
        """
        get_grouplist_cmd = ["/usr/bin/euare-grouplistbypath",
                             "--as-account", account]

        try:
            grplist, v = subprocess.Popen(get_grouplist_cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error: " + account + " Group List.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        groups = []
        sColon = re.compile('[:]')
        for group_info in grplist.splitlines():
            if re.search('iam', group_info):
                entry = sColon.split(group_info)
                group_id = entry[5].strip().split("/")
                groups.append(group_id[1])
        return groups

    def get_account_group_info(self, account, group):
        """
        Grab the resources of the groups in the Euare account passed in
        """
        self.get_cmd_output_now("/usr/bin/euare-grouplistusers --as-account "
                                + account + " -g " + group,
                                suggest_filename="euare-grouplistusers-"
                                + account + "-" + group)
        self.get_cmd_output_now("/usr/bin/euare-grouplistpolicies \
                              --as-account "
                                + account + " -g " + group
                                + " -v",
                                suggest_filename="euare-grouplistpolicies-"
                                + account + "-" + group)

    def get_rolelist(self, account):
        """
        Grab the roles from the Euare account passed in and return the list
        """
        get_rolelist_cmd = ["/usr/bin/euare-rolelistbypath",
                            "--as-account", account]

        try:
            rlist, v = subprocess.Popen(get_rolelist_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error: " + account + " Role List.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        roles = []
        sColon = re.compile('[:]')
        for role_info in rlist.splitlines():
            entry = sColon.split(role_info)
            role_id = entry[5].strip().split("/")
            roles.append(role_id[-1])
        return roles

    def get_account_role_info(self, account, role):
        """
        Grab the resources of the role in the Euare account passed in
        """
        self.get_cmd_output_now("/usr/bin/euare-rolelistpolicies --as-account "
                                + account + " -r " + role,
                                suggest_filename="euare-rolelistpolicies-"
                                + account + "-" + role)
        self.get_cmd_output_now("/usr/bin/euare-instanceprofilelistforrole "
                                + "--as-account "
                                + account + " -r " + role,
                                suggest_filename="euare-instprofilelistforrole-"
                                + account + "-" + role)

    def get_instprofile(self, account):
        """
        Grab instance profiles from the Euare account passed
        """
        get_profilelist_cmd = ["/usr/bin/euare-instanceprofilelistbypath",
                               "--as-account", account]

        try:
            plist, v = subprocess.Popen(get_profilelist_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.add_alert("Error: " + account + " Profile List.")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)
        profiles = []
        sColon = re.compile('[:]')
        for profile_info in plist.splitlines():
            entry = sColon.split(profile_info)
            profile_id = entry[5].strip().split("/")
            profiles.append(profile_id[-1])
        return profiles

    def get_account_instprofile(self, account, profile):
        """
        Grab the resources of instances profile in Euare account passed
        """
        self.get_cmd_output_now("/usr/bin/euare-instanceprofilegetattributes "
                                + "--as-account "
                                + account + " -s " + profile
                                + " -r ",
                                suggest_filename="euare-instprofileattributes-"
                                + account + "-" + profile)

    def get_stacks(self):
        """
        Grab the Cloudformation Stacks
        """
        get_stacklist_cmd = ["/usr/bin/euform-describe-stacks",
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
            if re.search('arn', stack_info):
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
        self.get_cmd_output_now("/usr/bin/euform-list-stack-resources "
                                + stack,
                                suggest_filename="euform-lst-stack-res-"
                                + stack_name
                                + "-" + stack_id)
        self.get_cmd_output_now("/usr/bin/euform-describe-stack-resources "
                                + "-n " + stack,
                                suggest_filename="euform-des-stack-res-"
                                + stack_name
                                + "-" + stack_id)
        self.get_cmd_output_now("/usr/bin/euform-describe-stack-events "
                                + stack,
                                suggest_filename="euform-des-stack-events-"
                                + stack_name
                                + "-" + stack_id)

    def get_instance_statuses(self):
        """
        Grab the status of the instances on the cloud
        """
        get_instanceslist_cmd = ["/usr/bin/euca-describe-instances",
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
                self.get_cmd_output_now("/usr/bin/euca"
                                        + "-describe-instance-status "
                                        + inst_id,
                                        suggest_filename="euca-des"
                                        + "-inst-status-"
                                        + "-" + inst_id)

    def cleanup(self, ini_file):
        """
        Clean up temp .ini file.
        """
        self.add_alert("### Clean up temp .ini file ###")
        try:
            os.remove(ini_file)
        except OSError:
            pass

    def eucalyptus_core(self):
        self.add_alert("### Grabbing eucalyptus/admin credentials ###")
        self.get_cmd_output_now("/usr/sbin/euca-describe-components",
                                suggest_filename="euca-describe-components")
        self.get_cmd_output_now("/usr/sbin/euca-describe-nodes",
                                suggest_filename="euca-describe-nodes")
        self.get_cmd_output_now("/usr/sbin/euca-describe-properties",
                                suggest_filename="euca-describe-properties")
        self.get_cmd_output_now("/usr/sbin/euca-describe-services --all -E",
                                suggest_filename="euca-describe-services-all")
        self.get_cmd_output_now("/usr/sbin/euca-describe-storage-controllers",
                                suggest_filename="euca-describe-storage"
                                + "-controllers")
        self.get_cmd_output_now("/usr/sbin/euca-describe-cloudwatch",
                                suggest_filename="euca-describe-cloudwatch")
        self.get_cmd_output_now("/usr/sbin/euca-describe-compute",
                                suggest_filename="euca-describe-compute")
        self.get_cmd_output_now("/usr/sbin/euca-describe-euare",
                                suggest_filename="euca-describe-euare")
        self.get_cmd_output_now("/usr/sbin/euca-describe-loadbalancing",
                                suggest_filename="euca-describe"
                                + "-loadbalancing")
        self.get_cmd_output_now("/usr/sbin/euca-describe-object"
                                + "-storage-gateways",
                                suggest_filename="euca-describe-osgs")
        self.get_cmd_output_now("/usr/sbin/euca-describe-tokens",
                                suggest_filename="euca-describe-tokens")
        self.get_cmd_output_now("/usr/sbin/euca-describe-walrusbackends",
                                suggest_filename="euca-describe"
                                + "-walrusbackends")
        self.get_cmd_output_now("/usr/bin/euctl"
                                + " -A",
                                suggest_filename="euctl-all")
        self.get_cmd_output_now("/usr/bin/euctl"
                                + " --dump cloud.network.network_configuration"
                                + " --format json",
                                suggest_filename="euctl-cloud.network.network_configuration.json")
        self.get_cmd_output_now("/usr/bin/euctl"
                                + " --dump cloud.network.network_configuration"
                                + " --format yaml",
                                suggest_filename="euctl-cloud.network.network_configuration.yaml")
        self.get_cmd_output_now("/usr/bin/euctl"
                                +
                                " --dump authentication.ldap_integration_configuration"
                                + " --format json",
                                suggest_filename="euctl-authentication.ldap_integration_configuration.json")
        self.get_cmd_output_now("/usr/bin/euctl"
                                +
                                " --dump authentication.ldap_integration_configuration"
                                + " --format yaml",
                                suggest_filename="euctl-authentication.ldap_integration_configuration.yaml")
        self.get_cmd_output_now("/usr/bin/euserv-describe-services"
                                + " --group-by-type",
                                suggest_filename="euserv-describe-services--group-by-type")
        self.get_cmd_output_now("/usr/bin/euserv-describe-services"
                                + " --group-by-zone",
                                suggest_filename="euserv-describe-services--group-by-zone")
        self.get_cmd_output_now("/usr/bin/euserv-describe-services"
                                + " --group-by-host",
                                suggest_filename="euserv-describe-services--group-by-host")
        self.get_cmd_output_now("/usr/bin/euserv-describe-services"
                                + " --expert",
                                suggest_filename="euserv-describe-services--expert")
        self.get_cmd_output_now("/usr/bin/euserv-describe-node-controllers",
                                suggest_filename="euserv-describe-node-controllers")
        self.get_cmd_output_now("/usr/bin/euserv-describe-service-types",
                                suggest_filename="euserv-describe-service-types")
        self.get_cmd_output_now("/usr/bin/euserv-describe-events",
                                suggest_filename="euserv-describe-events")
        self.get_cmd_output_now("/usr/bin/euca-version")

    def eucalyptus_ec2(self):
        self.add_alert("### Grabbing Cloud Resource Data ###")
        self.get_cmd_output_now("/usr/bin/euca-describe-addresses"
                                + " verbose",
                                suggest_filename="euca-describe-addrs-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-availability-zones"
                                + " verbose",
                                suggest_filename="euca-describe-a-z-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-instance-types"
                                + " --show-capacity --by-zone",
                                suggest_filename="euca-describe-inst-types")
        self.get_cmd_output_now("/usr/bin/euca-describe-groups"
                                + " verbose",
                                suggest_filename="euca-describe-grps-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-images"
                                + " --all",
                                suggest_filename="euca-describe-images-all")
        self.get_cmd_output_now("/usr/bin/euca-describe-regions",
                                suggest_filename="euca-describe-regions")
        self.get_cmd_output_now("/usr/bin/euca-describe-instances"
                                + " verbose",
                                suggest_filename="euca-describe-"
                                + "instances-verbose")
        self.get_cmd_output_now("/usr/bin/euca-describe-keypairs"
                                + " verbose",
                                suggest_filename="euca-describe-kyprs-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-volumes"
                                + " verbose",
                                suggest_filename="euca-describe-vols-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-tags",
                                suggest_filename="euca-describe-tags")
        self.get_cmd_output_now("/usr/bin/euca-describe-conversion-tasks"
                                + " verbose",
                                suggest_filename="euca-desc-con-tasks-v")

        self.get_instance_statuses()

        self.get_cmd_output_now("/usr/bin/euca-describe-vpcs"
                                + " verbose",
                                suggest_filename="euca-"
                                + "describe-vpcs-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-"
                                + "network-acls"
                                + " verbose",
                                suggest_filename="euca-"
                                + "describe-network-acls-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-"
                                + "route-tables"
                                + " verbose",
                                suggest_filename="euca-"
                                + "describe-route-tables-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-"
                                + " subnets"
                                + " verbose",
                                suggest_filename="euca-"
                                + "describe-subnets-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-snapshots"
                                + " --all",
                                suggest_filename="euca-describe"
                                + "-snpshts-v")
        self.get_cmd_output_now("/usr/bin/euca-describe-account-attributes",
                                suggest_filename="euca-describe-account-attributes")
        self.get_cmd_output_now("/usr/bin/euca-describe-customer-gateways",
                                suggest_filename="euca-describe-customer-gateways")
        self.get_cmd_output_now("/usr/bin/euca-describe-dhcp-options",
                                suggest_filename="euca-describe-dhcp-options")
        self.get_cmd_output_now("/usr/bin/euca-describe-internet-gateways",
                                suggest_filename="euca-describe-internet-gateways")
        self.get_cmd_output_now("/usr/bin/euca-describe-network-interfaces",
                                suggest_filename="euca-describe-network-interfaces")
        self.get_cmd_output_now("/usr/bin/euca-describe-vpc-peering-connections",
                                suggest_filename="euca-describe-vpc-peering-connections")
        self.get_cmd_output_now("/usr/bin/euca-describe-vpn-connections",
                                suggest_filename="euca-describe-vpn-connections")
        self.get_cmd_output_now("/usr/bin/euca-describe-vpn-gateways",
                                suggest_filename="euca-describe-vpn-gateways")
        self.get_cmd_output_now("/usr/bin/euca-describe-vpn-gateways",
                                suggest_filename="euca-describe-vpn-gateways")
        self.get_cmd_output_now("/usr/bin/euca-describe-snapshots"
                                + " verbose",
                                suggest_filename="euca-describe"
                                + "-snpshts-v")

    def eucalyptus_iam(self):
        self.get_cmd_output_now("/usr/bin/euare-accountlist",
                                suggest_filename="euare-accountlist")
        for account in self.get_accountlist():
            self.get_account_info(account)
            for user in self.get_userlist(account):
                self.get_account_user_info(account, user)
            for group in self.get_grouplist(account):
                self.get_account_group_info(account, group)

            self.get_cmd_output_now("/usr/bin/euare-accountlist",
                                    suggest_filename="euare-accountlist")
            for account in self.get_accountlist():
                self.get_account_info(account)
                for user in self.get_userlist(account):
                    self.get_account_user_info(account, user)
                for group in self.get_grouplist(account):
                    self.get_account_group_info(account, group)
                for role in self.get_rolelist(account):
                    self.get_account_role_info(account, role)
                for instprofile in self.get_instprofile(account):
                    self.get_account_instprofile(account, instprofile)

    def eucalyptus_autoscaling(self):
        self.get_cmd_output_now("/usr/bin/euscale-describe-auto"
                                + "-scaling-instances"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-a-s-insts-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-auto-scaling-groups"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-a-s-grps-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-launch-configs"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-l-cnfs-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-notification"
                                + "-configurations"
                                + " verbose",
                                suggest_filename="euscale-describe-not-cnfs-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-policies"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-pols-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-scaling-activities"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-s-a-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-scheduled-actions"
                                + " verbose --show-long",
                                suggest_filename="euscale-describe-sch-a-v")
        self.get_cmd_output_now("/usr/bin/euscale-describe-termination-policy-types",
                                suggest_filename="euscale-describe-termination-policy-types")

    def eucalyptus_elb(self):
        self.get_cmd_output_now("/usr/bin/eulb-describe-lb-policies"
                                + " verbose --show-long",
                                suggest_filename="eulb-describe-lb-pols-v")
        self.get_cmd_output_now("/usr/bin/eulb-describe-lb-policy-types"
                                + " verbose --show-long",
                                suggest_filename="eulb-describe-lb-pol-types-v")
        self.get_cmd_output_now("/usr/bin/eulb-describe-lbs"
                                + " verbose --show-long",
                                suggest_filename="eulb-describe-lbs-v")

    def eucalyptus_cloudwatch(self):
        self.get_cmd_output_now("/usr/bin/euwatch-describe-alarms"
                                + " verbose --show-long",
                                suggest_filename="euwatch-describe-alrms-v")
        self.get_cmd_output_now("/usr/bin/euwatch-describe-alarm-history"
                                + " verbose --show-long",
                                suggest_filename="euwatch-describe-alrm-hist-v")
        self.get_cmd_output_now("/usr/bin/euwatch-list-metrics",
                                suggest_filename="euwatch-list-metrics")

    def eucalyptus_cloudformation(self):
        self.get_cmd_output_now("/usr/bin/euform-describe-stacks"
                                + " verbose --show-long",
                                suggest_filename="euform-describe-stacks-v")
        for stack in self.get_stacks():
            self.get_cloudformation_resources(stack)

    def setup(self):
        if self.checkenabled():
            self.add_alert("### Check eucalyptus-cloud is running ###")
            self.clc_status()

            self.add_alert("### Setting up sosreport.ini credentials file ###")
            ini_file = self.euca2ools_conf_setup()

            self.add_alert(
                "### Adding eucalyptus/admin credentials to environment ###")
            os_env = self.update_env()
            os.environ = os_env

            self.add_alert("### Grab Eucalyptus Core Service Information ###")
            self.eucalyptus_core()

            self.add_alert("### Grab Eucalyptus EC2 Service Information ###")
            self.eucalyptus_ec2()

            self.add_alert("### Grab Eucalyptus IAM Service Information ###")
            self.eucalyptus_iam()

            euca2ools_version = self.checkversion('euca2ools')

            self.add_alert("### Grab AutoScaling Service Information ###")
            self.eucalyptus_autoscaling()

            self.add_alert("### Grab Load Balancing Service Information ###")
            self.eucalyptus_elb()

            self.add_alert("### Grab CloudWatch Service Information ###")
            self.eucalyptus_cloudwatch()

            self.add_alert("### Grab CloudFormation Service Information ###")
            self.eucalyptus_cloudformation()

            self.cleanup(ini_file)
        return
