#
# Conditional build:	
# _without_gnome - without gnome-askpass utility

Summary:	OpenSSH free Secure Shell (SSH) implementation
Summary(pl):	Publicznie dostêpna implementacja bezpiecznego shella (SSH)
Name:		openssh
Version:	3.0p1
Release:	1
License:	BSD
Group:		Applications/Networking
Group(de):	Applikationen/Netzwerkwesen
Group(pl):	Aplikacje/Sieciowe
Source0:	ftp://ftp.ca.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
Source1:	%{name}d.conf
Source2:	%{name}.conf
Source3:	%{name}d.init
Source4:	%{name}d.pamd
Source5:	%{name}.sysconfig
Source6:	passwd.pamd
Patch0:		%{name}-libwrap.patch
Patch1:		%{name}-no_libnsl.patch
Patch2:		%{name}-no-openssl-ver-check.patch
Patch3:		%{name}-set_12.patch
URL:		http://www.openssh.com/
BuildRequires:	XFree86-devel
BuildRequires:	autoconf
BuildRequires:	automake
%{!?_without_gnome:BuildRequires: gnome-libs-devel}
BuildRequires:	openssl-devel >= 0.9.6a
BuildRequires:	pam-devel
BuildRequires:	zlib-devel
BuildRequires:	libwrap-devel
BuildRequires:	perl
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Prereq:		openssl
Obsoletes:	ssh

%define		_sysconfdir	/etc/ssh
%define		_libexecdir	%{_libdir}/%{name}

%description
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing
it up to date in terms of security and features, as well as removing
all patented algorithms to seperate libraries (OpenSSL).

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%description -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Summary(pl):	Klienci protoko³u Secure Shell
Requires:	openssh
Group:		Applications/Networking
Group(de):	Applikationen/Netzwerkwesen
Group(pl):	Aplikacje/Sieciowe
Obsoletes:	ssh-clients
Requires:	%{name} = %{version}

%description clients
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing
it up to date in terms of security and features, as well as removing
all patented algorithms to seperate libraries (OpenSSL).

This package includes the clients necessary to make encrypted
connections to SSH servers.

%description -l pl clients
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera klientów s³u¿±cych do ³±czenia siê z serwerami SSH.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Summary(pl):	Serwer protoko³u Secure Shell (sshd)
Requires:	openssh
Requires:	chkconfig >= 0.9
Group:		Networking/Daemons
Group(de):	Netzwerkwesen/Server
Group(pl):	Sieciowe/Serwery
Obsoletes:	ssh-server
Requires:	/bin/login
Requires:	util-linux
Prereq:		rc-scripts
Prereq:		/sbin/chkconfig
Prereq:		%{name} = %{version}

%description server
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing
it up to date in terms of security and features, as well as removing
all patented algorithms to seperate libraries (OpenSSL).

This package contains the secure shell daemon. The sshd is the server
part of the secure shell protocol and allows ssh clients to connect to
your host.

%description -l pl server
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera serwer sshd (do którego mog± ³±czyæ siê klienci
ssh).

%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Summary(pl):	Odpytywacz has³a OpenSSH dla GNOME
Group:		Applications/Networking
Group(de):	Applikationen/Netzwerkwesen
Group(pl):	Aplikacje/Sieciowe
Requires:	%{name} = %{version}
Obsoletes:	ssh-extras
Obsoletes:	ssh-askpass
Obsoletes:	openssh-askpass

%description gnome-askpass
Ssh (Secure Shell) a program for logging into a remote machine and for
executing commands in a remote machine. It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing
it up to date in terms of security and features, as well as removing
all patented algorithms to seperate libraries (OpenSSL).

This package contains the GNOME passphrase dialog.

%description -l pl gnome-askpass
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera ,,odpytywacz has³a'' dla GNOME.

%prep
%setup  -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
aclocal
autoconf
%configure \
	%{!?_without_gnome:--with-gnome-askpass} \
	--with-pam \
	--with-mantype=man \
	--with-md5-passwords \
	--with-ipaddr-display \
	--with-4in6 \
	--disable-suid-ssh \
	--with-tcp-wrappers \
	--with-pid-dir=%{_localstatedir}/run

echo '#define LOGIN_PROGRAM           "/bin/login"' >>config.h

%{__make}

%{!?_without_gnome: cd contrib && %{__cc} %{rpmcflags} `gnome-config --cflags gnome gnomeui gtk` } \
%{!?_without_gnome:	gnome-ssh-askpass.c -o gnome-ssh-askpass } \
%{!?_without_gnome:	`gnome-config --libs gnome gnomeui gtk` }

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir},/etc/{pam.d,rc.d/init.d,sysconfig,security}}

%{__make} install DESTDIR="$RPM_BUILD_ROOT"

install %{SOURCE4} $RPM_BUILD_ROOT/etc/pam.d/sshd
install %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/passwdssh
install %{SOURCE5} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/ssh_config
install %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/sshd_config
install -d $RPM_BUILD_ROOT%{_libexecdir}/ssh
%{!?_without_gnome:install contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass}

rm -f	$RPM_BUILD_ROOT%{_mandir}/man1/slogin.1
echo ".so man1/ssh.1" > $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1

gzip -9nf *.RNG TODO README OVERVIEW CREDITS Change*

touch $RPM_BUILD_ROOT/etc/security/blacklist.sshd
	
%clean
rm -rf $RPM_BUILD_ROOT

%post server
/sbin/chkconfig --add sshd
if [ -f /var/lock/subsys/sshd ]; then
	/etc/rc.d/init.d/sshd restart 1>&2
else
	echo "Run \"/etc/rc.d/init.d/sshd start\" to start openssh daemon."
fi
if ! grep ssh /etc/security/passwd.conf >/dev/null 2>&1 ; then
	echo "ssh" >> /etc/security/passwd.conf
fi

%preun server
if [ "$1" = "0" ]; then
	if [ -f /var/lock/subsys/sshd ]; then
		/etc/rc.d/init.d/sshd stop 1>&2
	fi
	/sbin/chkconfig --del sshd
fi

%files
%defattr(644,root,root,755)
%doc *.gz
%attr(755,root,root) %{_bindir}/ssh-key*
%{_mandir}/man1/ssh-key*.1*
%dir %{_sysconfdir}

%files clients
%defattr(644,root,root,755)
%attr(0755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/slogin
%attr(0755,root,root) %{_bindir}/sftp
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(755,root,root) %{_bindir}/scp
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/slogin.1*
%{_mandir}/man1/sftp.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/ssh_config

%files server
%defattr(644,root,root,755)
%attr(755,root,root) %{_sbindir}/sshd
%attr(755,root,root) %{_libexecdir}/sftp-server
%dir %{_libexecdir}
%{_mandir}/man8/sshd.8*
%{_mandir}/man8/sftp-server.8*
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/sshd_config
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/pam.d/sshd
%attr(640,root,root) %{_sysconfdir}/moduli
%attr(754,root,root) /etc/rc.d/init.d/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/sysconfig/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/security/blacklist.sshd

%{!?_without_gnome:%files gnome-askpass}
%{!?_without_gnome:%defattr(644,root,root,755)}
%{!?_without_gnome:%dir %{_libexecdir}/ssh}
%{!?_without_gnome:%attr(755,root,root) %{_libexecdir}/ssh/ssh-askpass}
