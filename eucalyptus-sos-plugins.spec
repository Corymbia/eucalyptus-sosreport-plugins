%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

Summary:       A plugin to sosreport to collect data about Eucalyptus clouds
Name:          eucalyptus-sos-plugins
Version:       0.5.1
Release:       1%{?build_id:.%build_id}%{?dist}
License:       GPLv2+
Group:         Applications/System
Url:           http://github.com/eucalyptus/eucalyptus-sosreport-plugins
BuildArch:     noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools
Requires:      sos >= 3

Source0:       %{tarball_basedir}.tar.xz


%description
Eucalyptus is open source software for building AWS-compatible
private and hybrid clouds. Sosreport is a set of tools that
gathers information about system hardware and configuration.
This package contains plugins for sosreport to gather
information on Eucalyptus clouds.


%prep
%setup -q -n %{tarball_basedir}


%build
%{__python2} setup.py build


%install
%{__python2} setup.py install --skip-build --root $RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT/%{python_sitelib}/sos/__init__.py*
rm $RPM_BUILD_ROOT/%{python_sitelib}/sos/plugins/__init__.py*


%files
%defattr(-,root,root,-)
%{python_sitelib}/sos/plugins/*
%{python_sitelib}/*.egg-info


%changelog
* Mon May 08 2017 Garrett Holmstrom <gholms@dxc.com> - 0.5.1
- Bump rpm Version tag

* Mon May 08 2017 Jim Carroll <jim.carroll@dxc.com> - 0.5.1
- Improvements to Midonet data collection
- Improvements to basic Eucalyptus data collection
- Added federation data collection
- Minor refactoring/cleanup

* Fri Nov 11 2016 Jim Carroll <jim.carroll@hpe.com> - 0.5.0
- First effort to add Midonet and related commands
  (new eucamidonet plugin)
- Added .blobstore files to be collected (eucanode)

* Fri Aug 12 2016 Jim Carroll <jim.carroll@hpe.com> - 0.4.1
- Improved creds checking/setup via environment variables
- Separated the common env vars check/setup block for all euca2ools_*
  plugins to new euca_common module

* Tue Aug 2 2016 Jim Carroll <jim.carroll@hpe.com> - 0.4.0
- General code cleanup and data collection optimizations (mainly no longer
  collecting rarely used items of either exceptional size or which take
  a long time to collect)
- Added support for RHEL/CentOS 7
- Refactored eucafrontend into separate euca2ools_* plugins; set
  euca2ools_euare to be 'optional' (not implicitly collected) by default

* Wed Jun 29 2016 Jim Carroll <jim.carroll@hpe.com> - 0.3.0
- Removed support for EOL items, such as VMware
- Changed PostgreSQL code to be more dynamic
- Separated logfile collection into its own plugin
- Improved eucaconsole logfile collection
- Added collection of authentication.ldap_integration_configuration
  and cloud.network.network_configuration (via euctl)

* Fri Jan 29 2016 Jim Carroll <jim.carroll@hpe.com> - 0.2.2
- Added support for new commands available in 3.x
- Added NC collection of GNI and related

* Thu Aug 20 2015 Matt Bacchi <matt.bacchi@hp.com> - 0.2.0
- Major changes to support sos 3.x api only.  We don't support sos 2.x as of version 0.2.0.

* Wed May 13 2015 Matt Bacchi <matt.bacchi@hp.com> - 0.1.8
- reworked eucameta.py functionality to prevent sos trying to load it as a plugin

* Tue Mar 10 2015 Garrett Holmstrom <gholms@fedoraproject.org> - 0.1.7
- Removed __init__.py files that conflict with the sos package
- Macro-ized tarball names and release numbers for use with rel-eng build system

* Fri Feb 13 2015 Garrett Holmstrom <gholms@fedoraproject.org> - 0.1.7-1
- Revamped build process
- Switched to noarch
- Add *.egg-info to files list
