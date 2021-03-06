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
import glob
import subprocess
import shlex


class eucacore(Plugin, RedHatPlugin):

    """Eucalyptus Cloud - Core
    """

    def checkenabled(self):
        if self.is_installed("eucalyptus"):
            return True
        return False

    def check_yum_history(self):
        self.add_cmd_output("yum history")
        yum_cmd = "yum history"
        yum_cmd_l = shlex.split(yum_cmd)
        (yum_hist_out, q) = \
            subprocess.Popen(yum_cmd_l,
                             stdout=subprocess.PIPE).communicate()
        try:
            # yum history first outputs 3 lines of info/headers
            # Fourth row, first col, should be most recent tx
            yum_hist_out_l = yum_hist_out.splitlines()
            yum_last_tx_row = yum_hist_out_l[3].split()
            yum_last_tx_id_str = yum_last_tx_row[0]
            yum_last_tx_id = int(yum_last_tx_id_str)
            for tx_id in range(1, yum_last_tx_id + 1):
                self.add_cmd_output("yum history info %d" % tx_id)
        except ValueError:
            self.add_alert("Failed to parse yum history")
        return

    def check_python_pip(self):
        if os.path.exists("/usr/bin/pip"):
            self.add_cmd_output("pip list")
        return

    def setup(self):
        if self.checkenabled():
            self.add_copy_spec("/etc/eucalyptus")
            self.add_copy_spec("/var/lib/eucalyptus/keys")
            self.add_copy_spec("/var/run/eucalyptus/*.xml")
            self.add_copy_spec("/var/run/eucalyptus/*.conf")
            self.add_copy_spec("/var/run/eucalyptus/*.pid")
            self.add_copy_spec(
                "/var/run/eucalyptus/global_network_info.version")
            self.add_copy_spec("/var/run/eucalyptus/nc-stats")
            self.add_copy_spec("/var/run/eucalyptus/net")
            if os.path.isfile('/usr/bin/sha1sum'):
                self.add_cmd_output("find /var/lib/eucalyptus/keys \
                                    -type f -print | \
                                    xargs -I {} sha1sum {}",
                                    suggest_filename="sha1sum-euca-keys")
            hprof_list = glob.glob('/var/log/eucalyptus/*.hprof')
            if hprof_list:
                self.add_cmd_output("rm -rf /var/log/eucalyptus/*.hprof",
                                    suggest_filename="hprof-removal")
            if os.path.isfile('/sbin/iptables-save'):
                self.add_cmd_output("/sbin/iptables-save --counters")
            if os.path.isfile('/sbin/ebtables-save'):
                self.add_cmd_output("/sbin/ebtables-save --counters")
            if os.path.isfile('/usr/sbin/ipset'):
                self.add_cmd_output([
                    "ipset -o xml list",
                    "ipset list"
                ])
            if os.path.isfile('/etc/pki/tls/certs/eucalyptus-enterprise.crt'):
                self.add_cmd_output("openssl x509 -text -in "
                                    + "/etc/pki/tls/certs/eucalyptus"
                                    + "-enterprise.crt"
                                    + " | grep -A 2 Validity",
                                    suggest_filename="euca-enterprise-cert"
                                    + "-validity")
                self.add_cmd_output("openssl x509 -text -in "
                                    + "/etc/pki/tls/certs/eucalyptus"
                                    + "-enterprise.crt"
                                    + " | grep -A 14 X509v3",
                                    suggest_filename="euca-enterprise-cert"
                                    + "-compliance")
            # check /tmp dir for sane owner/group/mode
            # mode '1777' also checks for sticky bit
            mode = os.stat("/tmp")
            if ((mode.st_uid != 0)
                    or (mode.st_gid != 0)
                    or (oct(mode.st_mode)[-4:] != '1777')):
                self.add_cmd_output("ls -ld /tmp",
                                    suggest_filename="tmp-dir-mode-fail")
            # gather a recursive listing of /var/lib/eucalyptus, including
            # dot-files
            self.add_cmd_output("ls -laR /var/lib/eucalyptus")
            # collect failed eucanetd files from /tmp (issue #94)
            self.add_copy_spec("/tmp/euca_*_failed")
            self.add_copy_spec("/tmp/hs_err_pid*.log")
            self.check_yum_history()
            self.check_python_pip()
        return
