%undefine _missing_build_ids_terminate_build

Name:           ntsclient
Version:        %{upstream_version}
Release:        1%{?dist}
Summary:        NTS Client in Golang

License:        ISC
URL:            https://gitlab.com/hacklunch/%{name}
Source0:        https://gitlab.com/hacklunch/%{name}/-/archive/%{version}/%{name}-%{version}.tar.gz

%if 0%{?rhel_version} || 0%{?centos_version} || 0%{?fedora}
BuildRequires: systemd-devel
BuildRequires: selinux-policy-devel
%else
#BuildRequires: libsystemd-dev
#BuildRequires: selinux-policy-dev
%endif

%description 
NTS client in Go to query for authenticated time.

%prep
test -d '%{name}-%{version}' && chmod -R u+w '%{name}-%{version}'

%setup -q -n ntsclient-%{version}

%build
mkdir -p ./_build/src/gitlab.com/hacklunch
ln -s $(pwd) ./_build/src/gitlab.com/hacklunch/ntsclient
export GOPATH=$(pwd)/_build:${gopath}

%make_build

# Build SElinux policy module
mkdir -p ./_build/selinux
cd ./_build/selinux

cat << 'EOF' > ntsclient.fc
%{_bindir}/ntsclient -- gen_context(system_u:object_r:ntsclient_exec_t,s0)
EOF

cat << 'EOF' > ntsclient.te
policy_module(ntsclient,1.0.0)
require {
type cert_t;
type net_conf_t;
type unreserved_port_t;
type dns_port_t;
type sysfs_t;
class tcp_socket name_connect;
class udp_socket name_connect;
class tcp_socket connect;
class udp_socket connect;
}
type ntsclient_t;
type ntsclient_conf_t;
type ntsclient_exec_t;
role system_r types ntsclient_t;
init_daemon_domain(ntsclient_t, ntsclient_exec_t)

allow ntsclient_t cert_t:dir { open read search };
allow ntsclient_t cert_t:file { getattr open read };
allow ntsclient_t cert_t:lnk_file { getattr read };
allow ntsclient_t net_conf_t:file { getattr open read };
allow ntsclient_t self:capability sys_time;
allow ntsclient_t self:tcp_socket { connect create getattr getopt setopt write read };
allow ntsclient_t self:udp_socket { connect create getattr setopt write read };
allow ntsclient_t unreserved_port_t:tcp_socket name_connect;
allow ntsclient_t sysfs_t:file { read open };
EOF

make -f /usr/share/selinux/devel/Makefile

%install
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}
install -p -m 0755 ./ntsclient %{buildroot}%{_bindir}/ntsclient
install -m 0644 ./contrib/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -m 0644 ./ntsclient.toml %{buildroot}%{_sysconfdir}/ntsclient.toml

install -d %{buildroot}%{_datarootdir}/selinux/packages
install -m 0644 ./_build/selinux/ntsclient.pp %{buildroot}%{_datarootdir}/selinux/packages/ntsclient.pp

%files
%{_bindir}/ntsclient
%{_sysconfdir}/ntsclient.toml
%{_unitdir}/%{name}.service
%{_datarootdir}/selinux/packages/ntsclient.pp

%doc README.md
%license LICENSE

%post
systemctl --no-reload preset %{name}.service >/dev/null 2>&1 || : 
semodule -i %{_datarootdir}/selinux/packages/ntsclient.pp 2>/dev/null || :
restorecon %{_bindir}/ntsclient 2>/dev/null || :
test -x /usr/sbin/setcap && /usr/sbin/setcap cap_sys_time=pe %{_bindir}/ntsclient 2>/dev/null || :

%preun
systemctl --no-reload disable --now %{name}.service >/dev/null 2>&1 || : 
semodule -r ntsclient 2>/dev/null || :

%changelog
* Tue Oct 29 2019 Stefan Midjich <swehack at gmail.com> - master
- Created RPM spec
