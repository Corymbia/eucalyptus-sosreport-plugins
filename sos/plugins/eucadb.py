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
        if (self.isInstalled("eucalyptus-cloud")
                and ((self.isInstalled("postgresql91")
                      and self.isInstalled("postgresql91-server"))
                     or (self.isInstalled("postgresql92")
                         and self.isInstalled("postgresql92-server")))):
            return True
        return False

    def check_postgres(self):
        """
        Check postgres process using pgrep (eucalyptus-cloud controls it)
        """
        pg_dirname = ''    # initialize
        postgres_pgrep_cmd = [
            "/usr/bin/pgrep",
            "-lf",
            "bin/postgres -D /var/lib/eucalyptus/db/data"]
        try:
            postgres_chk = subprocess.Popen(
                postgres_pgrep_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
        except OSError, e:
            if 'No such' in e.strerror:
                self.addDiagnose("Error checking postgres process status")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e)

        # postgres_chk will always be a 2-element list, where the last element
        # is always ''
        pg_proc = postgres_chk[0]
        pg_proc = pg_proc.rstrip()    # get rid of the trailing newline, if any

        if len(pg_proc) == 0:
            self.addDiagnose(
                "Error: No extant master postgres process running")
            raise

        else:
            pg_proc_l = pg_proc.split('\n')
            if len(pg_proc_l) > 1:
                self.addDiagnose(
                    "Error: More than one master postgres process running")
                raise
            else:
                # If we get to here, then we have exactly one
                # master postgres process.
                # Now we need to determine the dirname of the running binary;
                # we'll use the same dirname to craft the pg_dump command
                # later.
                pg_cmd = pg_proc_l[0].split()[1]
                pg_dirname = os.path.dirname(pg_cmd)

        return pg_dirname

    def dump_db_to_file(self, pg_dumpbin, db_datapath, db):
        (pg_dumpbin, db_datapath, db) = (pg_dumpbin, db_datapath, db)
        dump_cmd = "%s -c -o -h %s -p 8777 -U root %s" % (
            pg_dumpbin, db_datapath, db)
        dump_file = db + ".sql"
        self.collectExtOutput(
            dump_cmd,
            dump_file,
            timeout=600
        )

    def setup(self):
        db_datapath = "/var/lib/eucalyptus/db/data"
        pg_dirname = self.check_postgres()
        pg_dumpbin = pg_dirname + '/pg_dump'
        pg_sqlbin = pg_dirname + '/psql'
        if (
            os.path.isfile(pg_dumpbin) and
            len(pg_dirname) > 0
        ):
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
                    self.collectExtOutput(
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

        if (
            os.path.isfile(pg_sqlbin) and
            len(pg_dirname) > 0
        ):
            select_cmd = '"SELECT \
                 pg_database.datname,pg_database_size(pg_database.datname),\
                 pg_size_pretty(pg_database_size(pg_database.datname)) \
                 FROM pg_database ORDER BY pg_database_size DESC;"'
            sql_cmd = "%s -h %s -p 8777 -U root -c %s -d %s" % \
                (pg_sqlbin,
                 db_datapath,
                 select_cmd,
                 "database_events")
            self.collectExtOutput(
                sql_cmd,
                suggest_filename="database_sizes.txt",
                timeout=600
            )

        dbfiles_l = ["pg_hba.conf",
                     "pg_hba.conf.org",
                     "pg_ident.conf"
                     "postgresql.conf",
                     "postgresql.conf.org"]
        for db_file in dbfiles_l:
            db_fullfile = db_datapath + '/' + db_file
            if os.path.isfile(db_fullfile):
                self.addCopySpec(db_fullfile)

        return
