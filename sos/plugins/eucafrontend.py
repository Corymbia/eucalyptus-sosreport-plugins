## Copyright (C) 2013 Eucalyptus Systems, Inc., Richard Isaacson <richard@eucalyptus.com>

### This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import sos.plugintools
import os, subprocess
import re

class eucafrontend(sos.plugintools.PluginBase):
    """Eucalyptus Cloud - Frontend
    """
    def checkenabled(self):
        if self.isInstalled("euca2ools"):
            return True
        if self.isInstalled("eucalyptus-admin-tools"):
            return True
        return False

    def eucacreds_setup(self):
        getcreds_cmd = ["/usr/sbin/euca-get-credentials", "-a", "eucalyptus", "-u", "admin", "admin.zip"]
        unzip_cmd = ["/usr/bin/unzip", "admin.zip", "-d", "/tmp/eucacreds"]
        try:
            mkdir_output = os.mkdir("/tmp/eucacreds")
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error creating /tmp/eucacreds directory")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        try:
            getcreds_output = subprocess.Popen(getcreds_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error grabbing eucalyptus/admin creds. Is CLC up?")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        try:
            unzip_output = subprocess.Popen(unzip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error unzipping admin.zip")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        return

    def get_access_key(self):
        try:
            with open("/tmp/eucacreds/eucarc") as eucarc_file:
                for line in eucarc_file:
                    if re.search("^export AWS_ACCESS_KEY", line):
                        name, var = line.partition("=")[::2]
                        access_key = var.replace('\'','').strip()
                        return access_key
            if access_key is None:
                self.addDiagnose("Error grabbing AWS_ACCESS_KEY from /tmp/eucacreds/eucarc")
                raise
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error opening /tmp/eucacreds/eucarc")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
 
    def get_secret_key(self):
        try:
            with open("/tmp/eucacreds/eucarc") as eucarc_file:
                for line in eucarc_file:
                    if re.search("^export AWS_SECRET_KEY", line):
                        name, var = line.partition("=")[::2]
                        secret_key = var.replace('\'','').strip()
                        return secret_key
            if secret_key is None:
                self.addDiagnose("Error grabbing AWS_SECRET_KEY from /tmp/eucacreds/eucarc")
                raise
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error opening /tmp/eucacreds/eucarc")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
 
    def get_account_id(self):
        try:
            with open("/tmp/eucacreds/eucarc") as eucarc_file:
                for line in eucarc_file:
                    if re.search("^export EC2_USER_ID", line):
                        name, var = line.partition("=")[::2]
                        account_id = var.replace('\'','').strip()
                        return account_id
            if account_id is None:
                self.addDiagnose("Error grabbing EC2_USER_ID from /tmp/eucacreds/eucarc")
                raise
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error opening /tmp/eucacreds/eucarc")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 

    def get_s3_url(self):
        try:
            with open("/tmp/eucacreds/eucarc") as eucarc_file:
                for line in eucarc_file:
                    if re.search("^export S3_URL", line):
                        name, var = line.partition("=")[::2]
                        s3_url = var.strip()
                        return s3_url
            if s3_url is None:
                self.addDiagnose("Error grabbing S3_URL from /tmp/eucacreds/eucarc")
                raise
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error opening /tmp/eucacreds/eucarc")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        
    def get_ec2_url(self):
        try:
            with open("/tmp/eucacreds/eucarc") as eucarc_file:
                for line in eucarc_file:
                    if re.search("^export EC2_URL", line):
                        name, var = line.partition("=")[::2]
                        ec2_url = var.strip()
                        return ec2_url
            if ec2_url is None:
                self.addDiagnose("Error grabbing EC2_URL from /tmp/eucacreds/eucarc")
                raise
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error opening /tmp/eucacreds/eucarc")
                raise OSError(e)
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        
    def euca2ools_conf_setup(self):
        try:
            mkdir_output = os.mkdir("/etc/euca2ools/conf.d")
        except OSError, e:
            error_string = '%s' % e
            if 'No such' in error_string:
                self.addDiagnose("Error creating /etc/euca2ools/conf.d directory")
                raise OSError(e)
            elif 'File exist' in error_string:
                self.addDiagnose("WARN: %s" % e)
                pass
            else:
                self.addDiagnose("Error: %s" % e)
                raise OSError(e) 
        access_key = self.get_access_key()     
        secret_key = self.get_secret_key()
        account_id = self.get_account_id()
        s3_url = self.get_s3_url()
        euca2ools_conf = open('/etc/euca2ools/conf.d/sos-euca2ools.ini', 'w')
        try:
            euca2ools_conf.write("[user admin]\n") 
            euca2ools_conf.write("key-id = " + access_key + "\n")
            euca2ools_conf.write("secret-key = " + secret_key + "\n")
            euca2ools_conf.write("account-id = " + account_id + "\n\n")
            euca2ools_conf.write("[region sosreport]\n")
            euca2ools_conf.write("autoscaling-url = http://127.0.0.1:8773/services/AutoScaling/\n")
            euca2ools_conf.write("ec2-url = http://127.0.0.1:8773/services/Eucalyptus/\n")
            euca2ools_conf.write("elasticloadbalancing-url = http://127.0.0.1:8773/services/LoadBalancing/\n")
            euca2ools_conf.write("iam-url = http://127.0.0.1:8773/services/Euare/\n")
            euca2ools_conf.write("monitoring-url = http://127.0.0.1:8773/services/CloudWatch/\n")
            euca2ools_conf.write("s3-url = " + s3_url + "/" + "\n")
            euca2ools_conf.write("sts-url = http://127.0.0.1:8773/services/Tokens/\n")
            euca2ools_conf.write("configuration-url = http://127.0.0.1:8773/services/Configuration/\n")
            euca2ools_conf.write("empyrean-url = http://127.0.0.1:8773/services/Empyrean/\n")
            euca2ools_conf.write("properties-url = http://127.0.0.1:8773/services/Properties/\n")
            euca2ools_conf.write("reporting-url = http://127.0.0.1:8773/services/Reporting/\n")
            euca2ools_conf.write("certificate = /var/lib/eucalyptus/keys/cloud-cert.pem\n")
        finally:
            euca2ools_conf.close()
            self.addDiagnose("Populated /etc/euca2ools/conf.d/sos-euca2ools.ini with admin creds")

    def cleanup(self):
        self.addDiagnose("### Cleanup credentials ###")
        self.collectExtOutput("rm -rf /tmp/eucacreds", suggest_filename="cleanup-eucacreds")
        self.collectExtOutput("rm -rf /tmp/admin.zip", suggest_filename="cleanup-admin-zip")
        self.collectExtOutput("rm -rf /etc/euca2ools/conf.d/sos-euca2ools.ini", suggest_filename="cleanup-sos-euca2ools-config")
 
    def setup(self):
        self.addDiagnose("### Grabbing eucalyptus/admin credentials ###")
        self.eucacreds_setup()
        self.addDiagnose("### Setting up sos-euca2ools.ini file ###")
        self.euca2ools_conf_setup()
        self.addCopySpec("/etc/euca2ools")
        self.addCopySpec("/tmp/eucacreds")
        self.addDiagnose("### Grabbing Cloud Resource Data ###")
        self.collectExtOutput("/usr/bin/euca-describe-addresses verbose --region admin@sosreport", suggest_filename="euca-describe-addresses-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-availability-zones verbose --region admin@sosreport", suggest_filename="euca-describe-availability-zones-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-groups verbose --region admin@sosreport", suggest_filename="euca-describe-groups-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-images --all --region admin@sosreport", suggest_filename="euca-describe-images-all")
        self.collectExtOutput("/usr/bin/euca-describe-instances verbose --region admin@sosreport", suggest_filename="euca-describe-instances-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-keypairs verbose --region admin@sosreport", suggest_filename="euca-describe-keypairs-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-snapshots verbose --region admin@sosreport", suggest_filename="euca-describe-snapshots-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-volumes verbose --region admin@sosreport", suggest_filename="euca-describe-volumes-verbose")
        self.collectExtOutput("/usr/bin/euca-describe-tags --region admin@sosreport", suggest_filename="euca-describe-tags-verbose")
        self.addDiagnose("### Grabbing Cloud Component Data ###")
        access_key = self.get_access_key()     
        secret_key = self.get_secret_key()
        ec2_url = self.get_ec2_url()
        self.collectExtOutput("/usr/sbin/euca-describe-arbitrators -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-arbitrators")
        self.collectExtOutput("/usr/sbin/euca-describe-clouds -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-clouds")
        self.collectExtOutput("/usr/sbin/euca-describe-clusters -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-clusters")
        self.collectExtOutput("/usr/sbin/euca-describe-components -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-components")
        self.collectExtOutput("/usr/sbin/euca-describe-nodes -U http://127.0.0.1:8773/services/Empyrean/ -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-nodes")
        self.collectExtOutput("/usr/sbin/euca-describe-properties -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-properties")
        self.collectExtOutput("/usr/bin/euca-describe-regions -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-regions")
        self.collectExtOutput("/usr/sbin/euca-describe-services --all -E", suggest_filename="euca-describe-services-all")
        self.collectExtOutput("/usr/sbin/euca-describe-storage-controllers -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-storage-controllers")
        self.collectExtOutput("/usr/sbin/euca-describe-vmware-brokers -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-vmware-brokers")
        self.collectExtOutput("/usr/sbin/euca-describe-walruses -U " + ec2_url + " -I " + access_key + " -S " + secret_key, suggest_filename="euca-describe-walruses")
        self.collectExtOutput("/usr/bin/euca-version")
        self.cleanup()
        return

