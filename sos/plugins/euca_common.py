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

# euca_common - Eucalyptus module of common functions

import os
import subprocess
import re


def update_env():
    # let's set a strict PATH for easy/trusted cmd access
    os_path = "/sbin:/bin:/usr/sbin:/usr/bin"
    os.environ['PATH'] = os_path

    # if none of these keys are found (no intersection)
    # then let's do a best effort
    env_keys_l = ['EC2_ACCESS_KEY',
                  'EC2_SECRET_KEY',
                  'AWS_DEFAULT_REGION']
    if not any(key in os.environ.keys() for key in env_keys_l):
        os.environ['AWS_DEFAULT_REGION'] = 'admin@localhost'

        # next, let's assure ourselves of having some sort
        # of guaranteed credentials, if on the CLC
        cmd = '/usr/sbin/clcadmin-assume-system-credentials'
        if os.path.isfile(cmd):
            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE
                                 ).communicate()[0]
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

            # set env vars from list
            env_add_d = dict(map(lambda x: x.split('='), env_add_l))
            os.environ.update(env_add_d)

            # remove env vars meant to be unset
            for k in env_remove_l:
                os.environ.pop(k, None)

    # finally, share back the env var changes to the env
    os_env = os.environ.copy()
    return os_env


def print_env():
    test_env = update_env()
    for k in test_env:
        print "%s=%s" % (k, test_env[k])

if __name__ == '__main__':
    print_env()
