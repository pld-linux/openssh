#
# Conditional build:	
# _without_gnome - without gnome-askpass utility
# _without_embed - don't build uClibc version

Summary:	OpenSSH free Secure Shell (SSH) implementation
Summary(es):	Implementación libre de SSH
Summary(pl):	Publicznie dostêpna implementacja bezpiecznego shella (SSH)
Summary(pt_BR):	Implementação livre do SSH
Name:		openssh
Version:	3.0.2p1
Release:	2
License:	BSD
Group:		Applications/Networking
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
%if %{!?_without_embed:1}%{?_without_embed:0}
BuildRequires:	uClibc-devel
BuildRequires:	uClibc-static
BuildRequires:	openssl-devel-embed
BuildRequires:	zlib-devel-embed
%endif
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Prereq:		openssl
Obsoletes:	ssh

%define embed_path	/usr/lib/embed
%define embed_cc	%{_arch}-uclibc-cc
%define embed_cflags	%{rpmcflags} -Os

%define embed_binaries	ssh scp sshd ssh-keygen

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

%description -l es
SSH es un programa para accesar y ejecutar órdenes en computadores
remotos. Sustituye rlogin y rsh, y suministra un canal de comunicación
seguro entre dos servidores en una red insegura. Conexiones X11 y
puertas TCP/IP arbitrárias también pueden ser usadas por el canal
seguro.

OpenSSH es el resultado del trabajo del equipo de OpenBSD para
continuar la última versión gratuita de SSH, actualizándolo en
términos de seguridad y recursos,así también eliminando todos los
algoritmos patentados y colocándolos en bibliotecas separadas
(OpenSSL).

Este paquete contiene "port" para Linux de OpenSSH. Se debe instalar
también el paquete openssh-clients u openssh-server o ambos.

%description -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

%description -l pt_BR
SSH é um programa para acessar e executar comandos em máquinas
remotas. Ele substitui rlogin e rsh, e provem um canal de comunicação
seguro entre dois hosts em uma rede insegura. Conexões X11 e portas
TCP/IP arbitrárias também podem ser usadas pelo canal seguro.

OpenSSH é o resultado do trabalho da equipe do OpenBSD em continuar a
última versão gratuita do SSH, atualizando-o em termos de segurança e
recursos, assim como removendo todos os algoritmos patenteados e
colocando-os em bibliotecas separadas (OpenSSL).

Esse pacote contém o "port" pra Linux do OpenSSH. Você deve instalar
também ou o pacote openssh-clients, ou o openssh-server, ou ambos.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Summary(es):	Clientes de OpenSSH
Summary(pl):	Klienci protoko³u Secure Shell
Summary(pt_BR):	Clientes do OpenSSH
Requires:	openssh
Group:		Applications/Networking
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

%description -l es clients
Este paquete incluye los clientes que se necesitan para hacer
conexiones codificadas con servidores SSH.

%description -l pl clients
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera klientów s³u¿±cych do ³±czenia siê z serwerami SSH.

%description -l pt_BR clients
Esse pacote inclui os clientes necessários para fazer conexões
encriptadas com servidores SSH.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Summary(es):	Servidor OpenSSH para comunicaciones codificadas
Summary(pl):	Serwer protoko³u Secure Shell (sshd)
Summary(pt_BR):	Servidor OpenSSH para comunicações encriptadas
Requires:	openssh
Requires:	chkconfig >= 0.9
Group:		Networking/Daemons
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

%description server -l es
Este paquete contiene el servidor SSH. sshd es la parte servidor del
protocolo secure shell y permite que clientes ssh se conecten a su
servidor.

%description server -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera serwer sshd (do którego mog± ³±czyæ siê klienci
ssh).

%description server -l pt_BR
Esse pacote contém o servidor SSH. O sshd é a parte servidor do
protocolo secure shell e permite que clientes ssh se conectem ao seu
host.

%package embed
Summary:	OpenSSH Secure Shell for embedded applications
Summary:	OpenSSH Secure Shell dla aplikacji wbudowanych 
Requires:	openssh
Group:		Applications/Networking
Obsoletes:	ssh-clients

%description embed
OpenSSH for embedded enviroment. Client, server, scp and ssh-keygen.

%description -l pl embed
OpenSSH dla aplikacji wbudowanych. Klient, serwer, scp i ssh-keygen.


%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Summary(es):	Diálogo para introducción de passphrase para GNOME
Summary(pl):	Odpytywacz has³a OpenSSH dla GNOME
Summary(pt_BR):	Diálogo para entrada de passphrase para GNOME
Group:		Applications/Networking
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

%description gnome-askpass -l es 
Este paquete contiene un programa que abre una caja de diálogo para
entrada de passphrase en GNOME.

%description gnome-askpass -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera ,,odpytywacz has³a'' dla GNOME.

%description gnome-askpass -l pt_BR
Esse pacote contém um programa que abre uma caixa de diálogo para
entrada de passphrase no GNOME.

%prep
%setup  -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
aclocal
autoconf

%if %{!?_without_embed:1}%{?_without_embed:0}
%configure \
	--without-gnome-askpass \
	--without-pam \
	--without-shadow \
	--with-mantype=man \
	--with-md5-passwords \
	--with-ipaddr-display \
	--with-4in6 \
	--disable-suid-ssh \
	--without-tcp-wrappers \
	--with-pid-dir=%{_localstatedir}/run \
	CC=%{embed_cc} CFLAGS="%{embed_cflags}"

echo '#define LOGIN_PROGRAM           "/bin/login"' >>config.h
%{__make}

for f in %{embed_binaries} ; do
	mv -f $f $f-embed-shared
done

%{__make} LDFLAGS="'-static -L. -Lopenbsd-compat/'"

for f in %{embed_binaries} ; do
	mv -f $f $f-embed-static
done

%{__make} distclean
%endif

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

%{!?_without_gnome:cd contrib && %{__cc} %{rpmcflags} `gnome-config --cflags gnome gnomeui gtk` } \
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

%if %{!?_without_embed:1}%{?_without_embed:0}
install -d $RPM_BUILD_ROOT/%{embed_path}/{shared,static}
for f in %{embed_binaries} ; do
	install $f-embed-static $RPM_BUILD_ROOT/%{embed_path}/static/$f
	install $f-embed-shared $RPM_BUILD_ROOT/%{embed_path}/shared/$f
done
%endif

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

%if %{!?_without_embed:1}%{?_without_embed:0}
%files embed
%defattr(644,root,root,755)
%attr(755,root,root) %{embed_path}/*/*
%endif
