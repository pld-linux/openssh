Summary:	OpenSSH free Secure Shell (SSH) implementation
Name:		openssh
Version:	1.2.1pre24
Release:	2
Source0:	http://violet.ibs.com.au/openssh/files/%{name}-%{version}.tar.gz
Source1:	opensshd.conf
Source2:	openssh.conf
Source3:	opensshd.init
Source4:	opensshd.pamd
Source5:	openssh.sysconfig
Source6:	passwd.pamd
Patch1:		openssh-DESTDIR.patch
Patch2:		openssh-PAM_NEW_AUTHTOK.patch
Patch3:		http://www.misiek.eu.org/ipv6/openssh-1.2.1pre24-ipv6-03012000.patch.gz
License:	BSD
Group:		Applications/Networking
Group(pl):	Aplikacje/Sieciowe
BuildRequires:	openssl-devel >= 0.9.4-2
BuildRequires:	zlib-devel
BuildRequires:	pam-devel
BuildRequires:	XFree86-devel
BuildRequires:	gnome-libs-devel
BuildRoot:	/tmp/%{name}-%{version}-root
Obsoletes:	ssh <> %{version}

%define		_sysconfdir	/etc/ssh

%description
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace rlogin and
rsh, and provide secure encrypted communications between two untrusted hosts
over an insecure network. X11 connections and arbitrary TCP/IP ports can
also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it up
to date in terms of security and features, as well as removing all patented
algorithms to seperate libraries (OpenSSL).

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Requires:	openssh
Group:		Applications/Networking
Group(pl):	Aplikacje/Sieciowe
Obsoletes:	ssh-clients <> %{version}
Requires:	%{name} = %{version}

%description clients
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace rlogin and
rsh, and provide secure encrypted communications between two untrusted hosts
over an insecure network. X11 connections and arbitrary TCP/IP ports can
also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it up
to date in terms of security and features, as well as removing all patented
algorithms to seperate libraries (OpenSSL).

This package includes the clients necessary to make encrypted connections to
SSH servers.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Requires:	openssh chkconfig >= 0.9
Group:		Networking/Daemons
Group(pl):	Sieciowe/Serwery
Obsoletes:	ssh-server <> %{version}
Requires:	rc-scripts
Requires:	/bin/login
Requires:	util-linux
Prereq:		%{name} = %{version}

%description server
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace rlogin and
rsh, and provide secure encrypted communications between two untrusted hosts
over an insecure network. X11 connections and arbitrary TCP/IP ports can
also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it up
to date in terms of security and features, as well as removing all patented
algorithms to seperate libraries (OpenSSL).

This package contains the secure shell daemon. The sshd is the server part
of the secure shell protocol and allows ssh clients to connect to your host.

%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Group:		Applications/Networking
Group(pl):	Aplikacje/Sieciowe
Requires:	%{name} = %{version}
Obsoletes:	ssh-extras <> %{version}
Obsoletes:	ssh-askpass <> %{version}
Obsoletes:	openssh-askpass <> %{version}

%description gnome-askpass
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace rlogin
and rsh, and provide secure encrypted communications between two untrusted
hosts over an insecure network. X11 connections and arbitrary TCP/IP ports
can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it up
to date in terms of security and features, as well as removing all patented
algorithms to seperate libraries (OpenSSL).

This package contains the GNOME passphrase dialog.

%prep
%setup  -q
%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
autoconf
%configure \
	--with-gnome-askpass \
	--with-tcp-wrappers \
	--with-md5-passwords \
	--enable-ipv6 \
	--enable-log-auth 
	
#	--without-kerberos4 \
#	--without-afs \
#	--without-skey 

echo '#define LOGIN_PROGRAM           "/bin/login"' >>config.h

make

%install
rm -rf $RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT{%{_sysconfdir},/etc/{pam.d,rc.d/init.d,sysconfig}}

make install DESTDIR="$RPM_BUILD_ROOT"

install %{SOURCE4} $RPM_BUILD_ROOT/etc/pam.d/sshd
install %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/passwdssh
install %{SOURCE5} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/ssh_config
install %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/sshd_config

mv -f 	$RPM_BUILD_ROOT%{_libexecdir}/ssh/gnome-ssh-askpass \
	$RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass

gzip -9fn ChangeLog OVERVIEW COPYING.Ylonen README README.Ylonen UPGRADING \
	$RPM_BUILD_ROOT/%{_mandir}/man*/*
	
%clean
rm -rf $RPM_BUILD_ROOT

%post server
/sbin/chkconfig --add sshd
if [ ! -f /etc/ssh/ssh_host_key -o ! -s /etc/ssh/ssh_host_key ]; then
	/usr/bin/ssh-keygen -b 1024 -f /etc/ssh/ssh_host_key -N '' >&2
fi
if [ ! -f /var/lock/subsys/sshd ]; then
	/etc/rc.d/init.d/sshd restart >&2
fi
if ! grep ssh /etc/security/passwd.conf >/dev/null 2>&1 ; then
	echo "ssh" >> /etc/security/passwd.conf
fi

%preun server
if [ "$1" = 0 ]; then
	if [ ! -f /var/lock/subsys/sshd ]; then
		/etc/rc.d/init.d/sshd stop >&2
	fi
	/sbin/chkconfig --del sshd
fi

%files
%defattr(644,root,root,755)
%doc {ChangeLog,OVERVIEW,COPYING.Ylonen,README,README.Ylonen,UPGRADING}.gz
%attr(755,root,root) %{_bindir}/ssh-keygen
%{_mandir}/man1/ssh-keygen.1*
%dir %{_sysconfdir}

%files clients
%defattr(644,root,root,755)
# suid root ?
#%attr(4755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-add
#%attr(0755,root,root) %{_bindir}/slogin
%attr(755,root,root) %{_bindir}/scp
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
#%{_mandir}/man1/slogin.1
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/ssh_config

%files server
%defattr(644,root,root,755)
%attr(755,root,root) %{_sbindir}/sshd
%{_mandir}/man8/sshd.8*
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/sshd_config
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/pam.d/sshd
%attr(754,root,root) /etc/rc.d/init.d/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/sysconfig/sshd

%files gnome-askpass
%defattr(644,root,root,755)
%dir %{_libexecdir}/ssh
%attr(755,root,root) %{_libexecdir}/ssh/ssh-askpass
