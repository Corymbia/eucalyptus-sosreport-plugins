# Copyright (C) 2014 Eucalyptus Systems, Inc.

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
import subprocess
import csv


class eucanode(Plugin, RedHatPlugin):
    """Eucalyptus Cloud - Node Controller
    """
    def checkenabled(self):
        if self.isInstalled("libvirt"):
            return True
        return False

    def setup(self):
        conf = file('/etc/eucalyptus/eucalyptus.conf')
        for line in conf:
            if 'EDGE' in line:
                self.addCopySpec("/var/lib/eucalyptus/*.xml")

        self.collectExtOutput("/usr/bin/virsh list",
                              suggest_filename="virsh-list")

        virsh_result = subprocess.Popen("virsh list | tail -n +3",
                                        stdout=subprocess.PIPE, shell=True)
        output, err = virsh_result.communicate()
        reader = csv.DictReader(output.decode('ascii').splitlines(),
                                delimiter=' ',
                                skipinitialspace=True,
                                fieldnames=['id', 'name', 'state'])
        for row in reader:
            self.collectExtOutput("virsh dumpxml " + row['id'],
                                  suggest_filename=row['name'] + "_xml")
        return
