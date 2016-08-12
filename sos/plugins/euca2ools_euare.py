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


class euca2ools_euare(Plugin, RedHatPlugin):

    """euca2ools euare commands:
    - all euare-* commands
    """

    def default_enabled(self):
        # We don't want this enabled by default, since collecting
        # the myriad euare-* cmds can be quite time-consuming.
        # Exception basis only.
        return False

    def checkenabled(self):
        if (
            self.is_installed("euca2ools") and
            self.is_installed("eucalyptus-admin-tools") and
            self.is_installed("eucalyptus-cloud")
        ):
            return True
        return False

    def get_accountlist(self):
        """
        Grab a listing of Euare accounts and return the list
        """

        get_actlist_cmd = ["euare-accountlist", ]

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
        self.add_cmd_output([
            "euare-accountaliaslist --as-account " + account,
            "euare-accountlistpolicies -a " + account + " -v",
            "euare-userlistbypath --as-account " + account,
            "euare-grouplistbypath --as-account " + account,
            "euare-rolelistbypath --as-account " + account,
            "euare-instanceprofilelistbypath --as-account " + account
        ])

    def get_userlist(self, account):
        """
        Grab list of users of the Euare account; return the list of users
        """
        get_userlist_cmd = ["euare-userlistbypath",
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
        self.add_cmd_output("euare-usergetinfo --as-account "
                            + account + " -u " + user)
        self.add_cmd_output("euare-usergetloginprofile "
                            + "--as-account "
                            + account + " -u " + user)
        self.add_cmd_output("euare-userlistcerts --as-account "
                            + account + " -u " + user)
        self.add_cmd_output("euare-usergetattributes "
                            + "--as-account "
                            + account + " -u " + user
                            + " --show-extra")
        self.add_cmd_output("euare-userlistgroups "
                            + "--as-account "
                            + account + " -u " + user)
        self.add_cmd_output("euare-userlistkeys --as-account "
                            + account + " -u " + user)
        self.add_cmd_output("euare-userlistpolicies "
                            + "--as-account "
                            + account + " -u " + user
                            + " -v")

    def get_grouplist(self, account):
        """
        Grab the groups from the Euare account passed in and return the list
        """
        get_grouplist_cmd = ["euare-grouplistbypath",
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
        self.add_cmd_output("euare-grouplistusers --as-account "
                            + account + " -g " + group)
        self.add_cmd_output("euare-grouplistpolicies \
                              --as-account "
                            + account + " -g " + group
                            + " -v")

    def get_rolelist(self, account):
        """
        Grab the roles from the Euare account passed in and return the list
        """
        get_rolelist_cmd = ["euare-rolelistbypath",
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
        self.add_cmd_output("euare-rolelistpolicies --as-account "
                            + account + " -r " + role)
        self.add_cmd_output("euare-instanceprofilelistforrole "
                            + "--as-account "
                            + account + " -r " + role)

    def get_instprofile(self, account):
        """
        Grab instance profiles from the Euare account passed
        """
        get_profilelist_cmd = ["euare-instanceprofilelistbypath",
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
        self.add_cmd_output("euare-instanceprofilegetattributes "
                            + "--as-account "
                            + account + " -s " + profile
                            + " -r ")

    def eucalyptus_iam(self):
        self.add_cmd_output("euare-accountlist")
        for account in self.get_accountlist():
            self.get_account_info(account)
            for user in self.get_userlist(account):
                self.get_account_user_info(account, user)
            for group in self.get_grouplist(account):
                self.get_account_group_info(account, group)

            self.add_cmd_output("euare-accountlist")
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

    def setup(self):
        if self.checkenabled():
            self.add_alert(
                "### Updating environment variables ###")
            os_env = euca_common.update_env()
            os.environ = os_env

            self.add_alert("### Grab Eucalyptus IAM Service Information ###")
            self.eucalyptus_iam()
        return
