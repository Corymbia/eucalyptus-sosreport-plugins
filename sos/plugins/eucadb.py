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
import subprocess


class eucadb(Plugin, RedHatPlugin):

    """Eucalyptus Cloud - PostgreSQL
    """

    def checkenabled(self):
        if (self.is_installed("eucalyptus-cloud")
                and ((self.is_installed("postgresql91")
                     and self.is_installed("postgresql91-server"))
                     or (self.is_installed("postgresql92")
                         and self.is_installed("postgresql92-server"))
                     or (self.is_installed("postgresql")
                         and self.is_installed("postgresql-server")))):
            return True
        return False

    def check_postgres(self, db_datapath):
        """
        Check postgres process using pgrep (eucalyptus-cloud controls it)
        """
        pg_bindir = ''    # initialize
        ps_cmd = "bin/postgres -D %s" % db_datapath
        postgres_pgrep_cmd = [
            "/usr/bin/pgrep",
            "-lf",
            ps_cmd]
        try:
            postgres_chk = subprocess.Popen(
                postgres_pgrep_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
        except OSError, e:
            if 'No such' in e.strerror:
                self.add_alert("Error checking postgres process status")
                raise OSError(e)
            else:
                self.add_alert("Error: %s" % e)
                raise OSError(e)

        # postgres_chk will always be a 2-element list, where the last element
        # is always '' -- also get rid of the trailing newline, if any
        pg_proc = postgres_chk[0].rstrip()

        if len(pg_proc) == 0:
            self.add_alert(
                "Error: No extant master postgres process running")
            raise

        else:
            pg_proc_l = pg_proc.split('\n')
            if len(pg_proc_l) > 1:
                self.add_alert(
                    "Error: More than one master postgres process running")
                raise
            else:
                # If we get to here, then we have exactly one
                # master postgres process.
                # Now we need to determine the dirname of the running binary;
                # we'll use to update the PATH env var.
                pg_pid = pg_proc_l[0].split()[0]
                pg_cmd_l = subprocess.Popen([
                    "ps",
                    "-o",
                    "cmd=",
                    pg_pid],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()
                pg_cmd = pg_cmd_l[0].split()[0]
                pg_bindir = os.path.dirname(pg_cmd)

        return pg_bindir

    def update_env(self, pg_bindir):
        # Let's make sure the PATH env var is limited in scope.
        # We'll append PostgreSQL's binary path just in case it's
        # not in the usual location.
        os_path = "/sbin:/bin:/usr/sbin:/usr/bin:" + pg_bindir
        os.environ['PATH'] = os_path
        os_env = os.environ.copy()
        return os_env

    def dump_db_to_file(self, pg_dumpbin, db_datapath, db):
        (pg_dumpbin, db_datapath, db) = (pg_dumpbin, db_datapath, db)
        dump_cmd = "%s -c -o -h %s -p 8777 -U root %s" % (
            pg_dumpbin, db_datapath, db)
        dump_file = db + ".sql"
        self.get_cmd_output_now(
            dump_cmd,
            dump_file,
            timeout=600
        )

    def id_dbs_to_dump(self, db_datapath):
        pg_dumpbin = 'pg_dump'
        pg_sqlbin = 'psql'

        dblistcmd = pg_sqlbin + ' -h ' + db_datapath + ' -p 8777 -l'
        dblistcmd_l = dblistcmd.split()
        dblist_out = subprocess.Popen(
            dblistcmd_l,
            stdout=subprocess.PIPE
        ).communicate()[0].rstrip()
        # get just the first column
        dblist_short = [x.split()[0] for x in dblist_out.split('\n')]
        # remove all but euca* table names
        db_l = [x for x in dblist_short if x[:4] == 'euca']

        # Checking to see if we're using 'eucalyptus_shared', which is a
        # sure sign we're on at least v4.1.
        if 'eucalyptus_shared' in db_l:
            # Eucalyptus 4.1 and later
            # We need to get the schemas from 'eucalyptus_shared'.
            select_cmd = "SELECT schema_name FROM %s;" % \
                "information_schema.schemata"
            schemalistcmd = "%s -h %s -p 8777 -U root -c %s -d %s" % \
                (pg_sqlbin,
                 db_datapath,
                 'SELECT',
                 "eucalyptus_shared")
            # turn command string into Popen-friendly format
            schemalistcmd_l = schemalistcmd.split()
            # locate the dummy 'SELECT' string
            select_idx = schemalistcmd_l.index('SELECT')
            # replace 'SELECT' with actual query
            schemalistcmd_l[select_idx] = select_cmd
            schemalist_out = subprocess.Popen(
                schemalistcmd_l,
                stdout=subprocess.PIPE
            ).communicate()[0].rstrip()
            schemalist_short = [x.split()[0]
                                for x in schemalist_out.split('\n')]
            schema_l = [x for x in schemalist_short if x[:4] == 'euca']
            for schema in schema_l:
                sdump_cmd = "%s -c -o -h %s -p 8777 -U root %s -n %s" % (
                    pg_dumpbin, db_datapath, "eucalyptus_shared", schema)
                sdump_file = schema + ".sql"
                self.get_cmd_output_now(
                    sdump_cmd,
                    sdump_file,
                    timeout=600
                )

        else:
            # Eucalyptus prior to v4.1
            for db in db_l:
                self.dump_db_to_file(pg_dumpbin, db_datapath, db)

        # At this point, db_l is a list of only euca* table names. Let's be
        # sure to grab 'database_events', regardless of Eucalyptus version.
        self.dump_db_to_file(pg_dumpbin, db_datapath, 'database_events')

        select_cmd = '"SELECT \
             pg_database.datname,pg_database_size(pg_database.datname),\
             pg_size_pretty(pg_database_size(pg_database.datname)) \
             FROM pg_database ORDER BY pg_database_size DESC;"'
        sql_cmd = "%s -h %s -p 8777 -U root -c %s -d %s" % \
            (pg_sqlbin,
             db_datapath,
             select_cmd,
             "database_events")
        self.get_cmd_output_now(
            sql_cmd,
            suggest_filename="database_sizes.txt",
            timeout=600
        )

        return

    def copy_db_config_files(self, db_datapath):
        dbfiles_l = ["pg_hba.conf",
                     "pg_hba.conf.org",
                     "pg_ident.conf",
                     "postgresql.conf",
                     "postgresql.conf.org"]
        for db_file in dbfiles_l:
            db_fullfile = db_datapath + '/' + db_file
            self.add_copy_spec(db_fullfile)

        return

    def setup(self):
        if self.checkenabled():
            db_datapath = "/var/lib/eucalyptus/db/data"

            self.add_alert(
                "### Checking PostgreSQL validity, detecting bindir ###")
            pg_bindir = self.check_postgres(db_datapath)

            self.add_alert(
                "### Adding PostgreSQL path to environment ###")
            os_env = self.update_env(pg_bindir)
            os.environ = os_env

            self.add_alert(
                "### Exporting PostgreSQL DB to files ###")
            self.id_dbs_to_dump(db_datapath)

            self.add_alert(
                "### Copying PostgreSQL config files ###")
            self.copy_db_config_files(db_datapath)

        return
