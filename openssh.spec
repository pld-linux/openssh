# TODO:
# - add trigger to enable this:
#  * sshd(8): This release turns on pre-auth sandboxing sshd by default for
#   new installs, by setting UsePrivilegeSeparation=sandbox in sshd_config.
#
# Conditional build:
%bcond_without	audit		# sshd audit support
%bcond_with	gnome		# with gnome-askpass (GNOME 1.x) utility
%bcond_without	gtk		# without GTK+ (2.x)
%bcond_without	ldap		# with ldap support
%bcond_without	libedit		# without libedit (editline/history support in sftp client)
%bcond_without	kerberos5	# without kerberos5 support
%bcond_without	selinux		# build without SELinux support
%bcond_without	libseccomp	# use libseccomp for seccomp privsep (requires 3.5 kernel)
%bcond_with	hpn		# High Performance SSH/SCP - HPN-SSH including Cipher NONE (broken too often)
%bcond_without	tests

# gtk2-based gnome-askpass means no gnome1-based
%{?with_gtk:%undefine with_gnome}

%ifnarch x32
# libseccomp requires 3.5 kernel, avoid such requirement where possible (non-x32 arches)
%undefine	with_libseccomp
%endif

%define	sandbox %{?with_libseccomp:lib}seccomp_filter

%ifarch x32
%{!?with_libseccomp:%error openssh seccomp implementation is broken! do not disable libseccomp on x32}
%endif

%if "%{pld_release}" == "ac"
%define		pam_ver	0.79.0
%else
%define		pam_ver	1:1.1.8-5
%endif
Summary:	OpenSSH free Secure Shell (SSH) implementation
Summary(de.UTF-8):	OpenSSH - freie Implementation der Secure Shell (SSH)
Summary(es.UTF-8):	Implementación libre de SSH
Summary(fr.UTF-8):	Implémentation libre du shell sécurisé OpenSSH (SSH)
Summary(it.UTF-8):	Implementazione gratuita OpenSSH della Secure Shell
Summary(pl.UTF-8):	Publicznie dostępna implementacja bezpiecznego shella (SSH)
Summary(pt.UTF-8):	Implementação livre OpenSSH do protocolo 'Secure Shell' (SSH)
Summary(pt_BR.UTF-8):	Implementação livre do SSH
Summary(ru.UTF-8):	OpenSSH - свободная реализация протокола Secure Shell (SSH)
Summary(uk.UTF-8):	OpenSSH - вільна реалізація протоколу Secure Shell (SSH)
Name:		openssh
Version:	7.1p2
Release:	1
Epoch:		2
License:	BSD
Group:		Applications/Networking
Source0:	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
# Source0-md5:	4d8547670e2a220d5ef805ad9e47acf2
Source1:	http://www.mif.pg.gda.pl/homepages/ankry/man-PLD/%{name}-non-english-man-pages.tar.bz2
# Source1-md5:	66943d481cc422512b537bcc2c7400d1
Source2:	%{name}d.init
Source3:	%{name}d.pamd
Source4:	%{name}.sysconfig
Source5:	ssh-agent.sh
Source6:	ssh-agent.conf
Source7:	%{name}-lpk.schema
Source9:	sshd.service
Source10:	sshd-keygen
Source11:	sshd.socket
Source12:	sshd@.service
Patch0:		%{name}-no_libnsl.patch
Patch1:		%{name}-tests-reuseport.patch
Patch2:		%{name}-pam_misc.patch
Patch3:		%{name}-sigpipe.patch
# http://pkgs.fedoraproject.org/gitweb/?p=openssh.git;a=tree
Patch4:		%{name}-ldap.patch
Patch5:		%{name}-ldap-fixes.patch
Patch6:		ldap.conf.patch
Patch7:		%{name}-config.patch
Patch8:		ldap-helper-sigpipe.patch
# High Performance SSH/SCP - HPN-SSH - http://www.psc.edu/networking/projects/hpn-ssh/
# http://www.psc.edu/networking/projects/hpn-ssh/openssh-5.2p1-hpn13v6.diff.gz
Patch9:		%{name}-5.2p1-hpn13v6.diff
Patch10:	%{name}-include.patch
Patch11:	%{name}-chroot.patch
Patch14:	%{name}-bind.patch
Patch15:	%{name}-disable_ldap.patch
Patch16:	libseccomp-sandbox.patch
URL:		http://www.openssh.com/portable.html
BuildRequires:	%{__perl}
%{?with_audit:BuildRequires:	audit-libs-devel}
BuildRequires:	autoconf >= 2.50
BuildRequires:	automake
%{?with_gnome:BuildRequires:	gnome-libs-devel}
%{?with_gtk:BuildRequires:	gtk+2-devel}
%{?with_kerberos5:BuildRequires:	heimdal-devel >= 0.7}
%{?with_libedit:BuildRequires:	libedit-devel}
BuildRequires:	libseccomp-devel
%{?with_selinux:BuildRequires:	libselinux-devel}
%{?with_ldap:BuildRequires:	openldap-devel}
BuildRequires:	openssl-devel >= 0.9.8f
BuildRequires:	pam-devel
%{?with_gtk:BuildRequires:	pkgconfig}
BuildRequires:	rpm >= 4.4.9-56
BuildRequires:	rpmbuild(macros) >= 1.627
BuildRequires:	sed >= 4.0
BuildRequires:	zlib-devel >= 1.2.3
%if %{with tests} && 0%(id -u sshd >/dev/null 2>&1; echo $?)
BuildRequires:	%{name}-server
%endif
%if %{with tests} && %{with libseccomp}
# libseccomp based sandbox requires NO_NEW_PRIVS prctl flag
BuildRequires:	uname(release) >= 3.5
%endif
Requires:	zlib >= 1.2.3
%if "%{pld_release}" == "ac"
Requires:	filesystem >= 2.0-1
Requires:	pam >= 0.79.0
%else
Requires:	filesystem >= 3.0-11
Requires:	pam >= %{pam_ver}
Suggests:	xorg-app-xauth
%endif
Obsoletes:	ssh
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_sysconfdir	/etc/ssh
%define		_libexecdir	%{_libdir}/%{name}
%define		_privsepdir	/usr/share/empty
%define		schemadir	/usr/share/openldap/schema

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

%if %{with hpn}
This release includes High Performance SSH/SCP patches from
http://www.psc.edu/networking/projects/hpn-ssh/ which are supposed to
increase throughput on fast connections with high RTT (20-150 msec).
See the website for '-w' values for your connection and /proc/sys TCP
values. BTW. in a LAN you have got generally RTT < 1 msec.
%endif

%description -l de.UTF-8
OpenSSH (Secure Shell) stellt den Zugang zu anderen Rechnern her. Es
ersetzt telnet, rlogin, rexec und rsh und stellt eine sichere,
verschlüsselte Verbindung zwischen zwei nicht vertrauenswürdigen Hosts
über eine unsicheres Netzwerk her. X11 Verbindungen und beliebige
andere TCP/IP Ports können ebenso über den sicheren Channel
weitergeleitet werden.

%description -l es.UTF-8
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

%description -l fr.UTF-8
OpenSSH (Secure Shell) fournit un accès à un système distant. Il
remplace telnet, rlogin, rexec et rsh, tout en assurant des
communications cryptées securisées entre deux hôtes non fiabilisés sur
un réseau non sécurisé. Des connexions X11 et des ports TCP/IP
arbitraires peuvent également être transmis sur le canal sécurisé.

%description -l it.UTF-8
OpenSSH (Secure Shell) fornisce l'accesso ad un sistema remoto.
Sostituisce telnet, rlogin, rexec, e rsh, e fornisce comunicazioni
sicure e crittate tra due host non fidati su una rete non sicura. Le
connessioni X11 ad una porta TCP/IP arbitraria possono essere
inoltrate attraverso un canale sicuro.

%description -l pl.UTF-8
Ssh (Secure Shell) to program służący do logowania się na zdalną
maszynę i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zastąpić rlogin, rsh i dostarczyć bezpieczne, szyfrowane połączenie
pomiędzy dwoma hostami.

Ten pakiet zawiera podstawowe pliki potrzebne zarówno po stronie
klienta jak i serwera OpenSSH. Aby był użyteczny, trzeba zainstalować
co najmniej jeden z pakietów: openssh-clients lub openssh-server.

%if %{with hpn}
Ta wersja zawiera łaty z projektu High Performance SSH/SCP
http://www.psc.edu/networking/projects/hpn-ssh/, które mają na celu
zwiększenie przepustowości transmisji dla szybkich połączeń z dużym
RTT (20-150 msec). Na stronie projektu znaleźć można odpowednie dla
danego połączenia wartości parametru '-w' oraz opcje /proc/sys dla
TCP. Nawiasem mówiąc w sieciach LAN RTT < 1 msec.
%endif

%description -l pt.UTF-8
OpenSSH (Secure Shell) fornece acesso a um sistema remoto. Substitui o
telnet, rlogin, rexec, e o rsh e fornece comunicações seguras e
cifradas entre duas máquinas sem confiança mútua sobre uma rede
insegura. Ligações X11 e portos TCP/IP arbitrários também poder ser
reenviados pelo canal seguro.

%description -l pt_BR.UTF-8
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

%description -l ru.UTF-8
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине. Она предназначена
для замены rlogin и rsh и обеспечивает безопасную шифрованную
коммуникацию между двумя хостами в сети, являющейся небезопасной.
Соединения X11 и любые порты TCP/IP могут также быть проведены через
безопасный канал.

OpenSSH - это переделка командой разработчиков OpenBSD последней
свободной версии SSH, доведенная до современного состояния в терминах
уровня безопасности и поддерживаемых возможностей. Все патентованные
алгоритмы вынесены в отдельные библиотеки (OpenSSL).

Этот пакет содержит файлы, необходимые как для клиента, так и для
сервера OpenSSH. Вам нужно будет установить еще openssh-clients,
openssh-server, или оба пакета.

%description -l uk.UTF-8
Ssh (Secure Shell) - це програма для "заходу" (login) до віддаленої
машини та для виконання команд на віддаленій машині. Вона призначена
для заміни rlogin та rsh і забезпечує безпечну шифровану комунікацію
між двома хостами в мережі, яка не є безпечною. З'єднання X11 та
довільні порти TCP/IP можуть також бути проведені через безпечний
канал.

OpenSSH - це переробка командою розробників OpenBSD останньої вільної
версії SSH, доведена до сучасного стану в термінах рівня безпеки та
підтримуваних можливостей. Всі патентовані алгоритми винесені до
окремих бібліотек (OpenSSL).

Цей пакет містить файли, необхідні як для клієнта, так і для сервера
OpenSSH. Вам потрібно буде ще встановити openssh-clients,
openssh-server, чи обидва пакети.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Summary(es.UTF-8):	Clientes de OpenSSH
Summary(pl.UTF-8):	Klienci protokołu Secure Shell
Summary(pt_BR.UTF-8):	Clientes do OpenSSH
Summary(ru.UTF-8):	OpenSSH - клиенты протокола Secure Shell
Summary(uk.UTF-8):	OpenSSH - клієнти протоколу Secure Shell
Group:		Applications/Networking
Requires:	%{name}
Provides:	ssh-clients
Obsoletes:	ssh-clients
%requires_eq_to	openssl	openssl-devel

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

%description clients -l es.UTF-8
Este paquete incluye los clientes que se necesitan para hacer
conexiones codificadas con servidores SSH.

%description clients -l pl.UTF-8
Ssh (Secure Shell) to program służący do logowania się na zdalną
maszynę i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zastąpić rlogin, rsh i dostarczyć bezpieczne, szyfrowane połączenie
pomiędzy dwoma hostami.

Ten pakiet zawiera klientów służących do łączenia się z serwerami SSH.

%description clients -l pt_BR.UTF-8
Esse pacote inclui os clientes necessários para fazer conexões
encriptadas com servidores SSH.

%description clients -l ru.UTF-8
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит программы-клиенты, необходимые для установления
зашифрованных соединений с серверами SSH.

%description clients -l uk.UTF-8
Ssh (Secure Shell) - це програма для "заходу" (login) до віддаленої
машини та для виконання команд на віддаленій машині.

Цей пакет містить програми-клієнти, необхідні для встановлення
зашифрованих з'єднань з серверами SSH.

%package clients-agent-profile_d
Summary:	OpenSSH Secure Shell agent init script
Summary(pl.UTF-8):	Skrypt startowy agenta OpenSSH
Group:		Applications/Networking
Requires:	%{name}-clients = %{epoch}:%{version}-%{release}

%description clients-agent-profile_d
profile.d scripts for starting SSH agent.

%description clients-agent-profile_d -l pl.UTF-8
Skrypty profile.d do uruchamiania agenta SSH.

%package clients-agent-xinitrc
Summary:	OpenSSH Secure Shell agent init script
Summary(pl.UTF-8):	Skrypt inicjujący agenta ssh przez xinitrc
Group:		Applications/Networking
Requires:	%{name}-clients-agent-profile_d = %{epoch}:%{version}-%{release}
Requires:	xinitrc

%description clients-agent-xinitrc
xinitrc scripts for starting SSH agent.

%description clients-agent-xinitrc -l pl.UTF-8
Skrypty xinitrc do uruchamiania agenta SSH.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Summary(de.UTF-8):	OpenSSH Secure Shell Protocol-Server (sshd)
Summary(es.UTF-8):	Servidor OpenSSH para comunicaciones codificadas
Summary(fr.UTF-8):	Serveur de protocole du shell sécurisé OpenSSH (sshd)
Summary(it.UTF-8):	Server OpenSSH per il protocollo Secure Shell (sshd)
Summary(pl.UTF-8):	Serwer protokołu Secure Shell (sshd)
Summary(pt.UTF-8):	Servidor do protocolo 'Secure Shell' OpenSSH (sshd)
Summary(pt_BR.UTF-8):	Servidor OpenSSH para comunicações encriptadas
Summary(ru.UTF-8):	OpenSSH - сервер протокола Secure Shell (sshd)
Summary(uk.UTF-8):	OpenSSH - сервер протоколу Secure Shell (sshd)
Group:		Networking/Daemons
Requires(post):	/sbin/chkconfig
Requires(post):	grep
Requires(post,preun):	/sbin/chkconfig
Requires(postun):	/usr/sbin/userdel
Requires(pre):	/bin/id
Requires(pre):	/usr/sbin/useradd
Requires(post,preun,postun):	systemd-units >= 38
Requires:	%{name} = %{epoch}:%{version}-%{release}
Requires:	pam >= %{pam_ver}
Requires:	rc-scripts >= 0.4.3.0
Requires:	systemd-units >= 38
%{?with_libseccomp:Requires:	uname(release) >= 3.5}
Requires:	util-linux
%{?with_ldap:Suggests:	%{name}-server-ldap}
Suggests:	/bin/login
Suggests:	xorg-app-xauth
Provides:	ssh-server
Provides:	user(sshd)
%requires_eq_to	openssl	openssl-devel

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

%description server -l de.UTF-8
Dieses Paket installiert den sshd, den Server-Teil der OpenSSH.

%description server -l es.UTF-8
Este paquete contiene el servidor SSH. sshd es la parte servidor del
protocolo secure shell y permite que clientes ssh se conecten a su
servidor.

%description server -l fr.UTF-8
Ce paquetage installe le 'sshd', partie serveur de OpenSSH.

%description server -l it.UTF-8
Questo pacchetto installa sshd, il server di OpenSSH.

%description server -l pl.UTF-8
Ssh (Secure Shell) to program służący do logowania się na zdalną
maszynę i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zastąpić rlogin, rsh i dostarczyć bezpieczne, szyfrowane połączenie
pomiędzy dwoma hostami.

Ten pakiet zawiera serwer sshd (do którego mogą łączyć się klienci
ssh).

%description server -l pt.UTF-8
Este pacote intala o sshd, o servidor do OpenSSH.

%description server -l pt_BR.UTF-8
Esse pacote contém o servidor SSH. O sshd é a parte servidor do
protocolo secure shell e permite que clientes ssh se conectem ao seu
host.

%description server -l ru.UTF-8
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит sshd - "демон" Secure Shell. sshd - это серверная
часть протокола Secure Shell, позволяющая клиентам ssh соединяться с
вашим хостом.

%description server -l uk.UTF-8
Ssh (Secure Shell) - це програма для "заходу" (login) до віддаленої
машини та для виконання команд на віддаленій машині.

Цей пакет містить sshd - "демон" Secure Shell. sshd - це серверна
частина протоколу Secure Shell, яка дозволяє клієнтам ssh зв'язуватись
з вашим хостом.

%package server-ldap
Summary:	A LDAP support for open source SSH server daemon
Summary(pl.UTF-8):	Wsparcie LDAP dla serwera OpenSSH
Group:		Daemons
Requires:	%{name} = %{epoch}:%{version}-%{release}
Requires:	openldap-nss-config

%description server-ldap
OpenSSH LDAP backend is a way how to distribute the authorized tokens
among the servers in the network.

%description server-ldap -l pl.UTF-8
Backend LDAP dla OpenSSH to metoda rozprowadzania autoryzowanych
tokenów między serwerami w sieci.

%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Summary(de.UTF-8):	OpenSSH GNOME Passwort-Dialog
Summary(es.UTF-8):	Diálogo para introducción de passphrase para GNOME
Summary(fr.UTF-8):	Dialogue pass-phrase GNOME d'OpenSSH
Summary(it.UTF-8):	Finestra di dialogo GNOME per la frase segreta di OpenSSH
Summary(pl.UTF-8):	Odpytywacz hasła OpenSSH dla GNOME
Summary(pt.UTF-8):	Diálogo de pedido de senha para GNOME do OpenSSH
Summary(pt_BR.UTF-8):	Diálogo para entrada de passphrase para GNOME
Summary(ru.UTF-8):	OpenSSH - диалог ввода ключевой фразы (passphrase) для GNOME
Summary(uk.UTF-8):	OpenSSH - діалог вводу ключової фрази (passphrase) для GNOME
Group:		Applications/Networking
Requires:	%{name} = %{epoch}:%{version}-%{release}
Obsoletes:	openssh-askpass
Obsoletes:	ssh-askpass
Obsoletes:	ssh-extras

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

%description gnome-askpass -l es.UTF-8
Este paquete contiene un programa que abre una caja de diálogo para
entrada de passphrase en GNOME.

%description gnome-askpass -l pl.UTF-8
Ssh (Secure Shell) to program służący do logowania się na zdalną
maszynę i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zastąpić rlogin, rsh i dostarczyć bezpieczne, szyfrowane połączenie
pomiędzy dwoma hostami.

Ten pakiet zawiera ,,odpytywacz hasła'' dla GNOME.

%description gnome-askpass -l pt_BR.UTF-8
Esse pacote contém um programa que abre uma caixa de diálogo para
entrada de passphrase no GNOME.

%description gnome-askpass -l ru.UTF-8
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит диалог ввода ключевой фразы для использования под
GNOME.

%description gnome-askpass -l uk.UTF-8
Ssh (Secure Shell) - це програма для "заходу" (login) до віддаленої
машини та для виконання команд на віддаленій машині.

Цей пакет містить діалог вводу ключової фрази для використання під
GNOME.

%package -n openldap-schema-openssh-lpk
Summary:	OpenSSH LDAP Public Key schema
Summary(pl.UTF-8):	Schemat klucza publicznego LDAP dla OpenSSH
Group:		Networking/Daemons
Requires(post,postun):	sed >= 4.0
Requires:	openldap-servers
%if "%{_rpmversion}" >= "5"
BuildArch:	noarch
%endif

%description -n openldap-schema-openssh-lpk
This package contains OpenSSH LDAP Public Key schema for openldap.

%description -n openldap-schema-openssh-lpk -l pl.UTF-8
Ten pakiet zawiera schemat klucza publicznego LDAP dla OpenSSH dla
openldap-a.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1

%{?with_hpn:%patch9 -p1}
%patch10 -p1
%patch11 -p1

%patch14 -p1
%{!?with_ldap:%patch15 -p1}
%{?with_libseccomp:%patch16 -p1}

%if "%{pld_release}" == "ac"
# fix for missing x11.pc
%{__sed} -i -e 's/\(`$(PKG_CONFIG) --libs gtk+-2.0\) x11`/\1` -lX11/' contrib/Makefile
%endif

# hack since arc4random from openbsd-compat needs symbols from libssh and vice versa
sed -i -e 's#-lssh -lopenbsd-compat#-lssh -lopenbsd-compat -lssh -lopenbsd-compat#g' Makefile*

grep -rl /usr/libexec/openssh/ssh-ldap-helper . | xargs \
%{__sed} -i -e 's,/usr/libexec/openssh/ssh-ldap-helper,%{_libexecdir}/ssh-ldap-helper,'

# prevent being ovewritten by aclocal calls
mv aclocal.m4 acinclude.m4

%build
cp /usr/share/automake/config.sub .
%{__aclocal}
%{__autoconf}
%{__autoheader}
CPPFLAGS="%{rpmcppflags} -DCHROOT -std=gnu99"
%configure \
	PERL=%{__perl} \
	--disable-strip \
	--enable-utmpx \
	--enable-wtmpx \
	--with-4in6 \
	%{?with_audit:--with-audit=linux} \
	--with-ipaddr-display \
	%{?with_kerberos5:--with-kerberos5=/usr} \
	--with-ldap%{!?with_ldap:=no} \
	%{?with_libedit:--with-libedit} \
	--with-mantype=man \
	--with-md5-passwords \
	--with-pam \
	--with-pid-dir=%{_localstatedir}/run \
	--with-privsep-path=%{_privsepdir} \
	--with-privsep-user=sshd \
	%{?with_selinux:--with-selinux} \
%if "%{pld_release}" == "ac"
	--with-xauth=/usr/X11R6/bin/xauth
%else
	--with-sandbox=%{sandbox} \
	--with-xauth=%{_bindir}/xauth
%endif

echo '#define LOGIN_PROGRAM		   "/bin/login"' >>config.h

%{__make}

%{?with_tests:%{__make} -j1 tests}

cd contrib
%if %{with gnome}
%{__make} gnome-ssh-askpass1 \
	CC="%{__cc} %{rpmldflags} %{rpmcflags}"
%endif
%if %{with gtk}
%{__make} gnome-ssh-askpass2 \
	CC="%{__cc} %{rpmldflags} %{rpmcflags}"
%endif

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir},/etc/{pam.d,rc.d/init.d,sysconfig,security,env.d}} \
	$RPM_BUILD_ROOT{%{_libexecdir}/ssh,%{schemadir},%{systemdunitdir}}
install -d $RPM_BUILD_ROOT/etc/{profile.d,X11/xinit/xinitrc.d}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

bzip2 -dc %{SOURCE1} | tar xf - -C $RPM_BUILD_ROOT%{_mandir}

install -p %{SOURCE2} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
cp -p %{SOURCE3} $RPM_BUILD_ROOT/etc/pam.d/sshd
cp -p %{SOURCE4} $RPM_BUILD_ROOT/etc/sysconfig/sshd
cp -p %{SOURCE5} $RPM_BUILD_ROOT/etc/profile.d
ln -sf /etc/profile.d/ssh-agent.sh $RPM_BUILD_ROOT/etc/X11/xinit/xinitrc.d/ssh-agent.sh
cp -p %{SOURCE6} $RPM_BUILD_ROOT%{_sysconfdir}
cp -p %{SOURCE7} $RPM_BUILD_ROOT%{schemadir}

cp -p %{SOURCE9} %{SOURCE11} %{SOURCE12} $RPM_BUILD_ROOT%{systemdunitdir}
install -p %{SOURCE10} $RPM_BUILD_ROOT%{_libexecdir}/sshd-keygen

%{__sed} -i -e 's|@@LIBEXECDIR@@|%{_libexecdir}|g' \
	$RPM_BUILD_ROOT/etc/rc.d/init.d/sshd \
	$RPM_BUILD_ROOT%{systemdunitdir}/sshd.service \
	$RPM_BUILD_ROOT%{_libexecdir}/sshd-keygen

%if %{with gnome}
install -p contrib/gnome-ssh-askpass1 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
%endif
%if %{with gtk}
install -p contrib/gnome-ssh-askpass2 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
%endif
%if %{with gnome} || %{with gtk}
cat << 'EOF' >$RPM_BUILD_ROOT/etc/env.d/GNOME_SSH_ASKPASS_GRAB_SERVER
#GNOME_SSH_ASKPASS_GRAB_SERVER="true"
EOF
cat << 'EOF' >$RPM_BUILD_ROOT/etc/env.d/GNOME_SSH_ASKPASS_GRAB_POINTER
#GNOME_SSH_ASKPASS_GRAB_POINTER="true"
EOF
ln -s %{_libexecdir}/ssh/ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/ssh-askpass
%endif

install -p contrib/ssh-copy-id $RPM_BUILD_ROOT%{_bindir}
cp -p contrib/ssh-copy-id.1 $RPM_BUILD_ROOT%{_mandir}/man1

%{__rm} $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1
echo ".so ssh.1" > $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1

touch $RPM_BUILD_ROOT/etc/security/blacklist.sshd

cat << 'EOF' > $RPM_BUILD_ROOT/etc/env.d/SSH_ASKPASS
#SSH_ASKPASS="%{_libexecdir}/ssh-askpass"
EOF

%if "%{pld_release}" == "ac"
# not present in ac, no point searching it
%{__sed} -i -e '/pam_keyinit.so/d' $RPM_BUILD_ROOT/etc/pam.d/sshd
# openssl on ac does not have OPENSSL_HAS_ECC
%{__sed} -i -e '/ecdsa/d' $RPM_BUILD_ROOT%{_libexecdir}/sshd-keygen
%endif

%if %{without audit}
# remove recording user's login uid to the process attribute
%{__sed} -i -e '/pam_loginuid.so/d' $RPM_BUILD_ROOT/etc/pam.d/sshd
%endif

%{__rm} $RPM_BUILD_ROOT%{_mandir}/README.openssh-non-english-man-pages
%{?with_ldap:%{__rm} $RPM_BUILD_ROOT%{_sysconfdir}/ldap.conf}

%clean
rm -rf $RPM_BUILD_ROOT

%post clients
%env_update

%postun clients
%env_update

%post gnome-askpass
%env_update

%postun gnome-askpass
%env_update

%pre server
%useradd -P %{name}-server -u 40 -d %{_privsepdir} -s /bin/false -c "OpenSSH PrivSep User" -g nobody sshd

%post server
/sbin/chkconfig --add sshd
%service sshd reload "OpenSSH Daemon"
NORESTART=1
%systemd_post sshd.service

%preun server
if [ "$1" = "0" ]; then
	%service sshd stop
	/sbin/chkconfig --del sshd
fi
%systemd_preun sshd.service

%postun server
if [ "$1" = "0" ]; then
	%userremove sshd
fi
%systemd_reload

%triggerpostun server -- %{name}-server < 2:7.0p1-2
%banner %{name}-server -e << EOF
!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!
! Starting from openssh 7.0 DSA keys are disabled !
! on server and client side. You will NOT be able !
! to use DSA keys for authentication. Please read !
! about PubkeyAcceptedKeyTypes in man ssh_config. !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF

%triggerpostun server -- %{name}-server < 6.2p1-1
cp -f %{_sysconfdir}/sshd_config{,.rpmorig}
sed -i -e 's#AuthorizedKeysCommandRunAs#AuthorizedKeysCommandUser##g' %{_sysconfdir}/sshd_config

%triggerpostun server -- %{name}-server < 2:5.9p1-8
# lpk.patch to ldap.patch
if grep -qE '^(UseLPK|Lpk)' %{_sysconfdir}/sshd_config; then
	echo >&2 "Migrating LPK patch to LDAP patch"
	cp -f %{_sysconfdir}/sshd_config{,.rpmorig}
	%{__sed} -i -e '
		# disable old configs
		# just UseLPK/LkpLdapConf supported for now
		s/^\s*UseLPK/## Obsolete &/
		s/^\s*Lpk/## Obsolete &/
		# Enable new ones, assumes /etc/ldap.conf defaults, see HOWTO.ldap-keys
		/UseLPK/iAuthorizedKeysCommand %{_libexecdir}/ssh-ldap-wrapper
	' %{_sysconfdir}/sshd_config
	if [ ! -x /bin/systemd_booted ] || ! /bin/systemd_booted; then
		/bin/systemctl try-restart sshd.service || :
	else
		%service -q sshd reload
	fi
fi
%systemd_trigger sshd.service
if [ -x /bin/systemd_booted ] && /bin/systemd_booted; then
%banner %{name}-server -e << EOF
!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
! Native systemd support for sshd has been installed.   !
! Restarting sshd.service with systemctl WILL kill all  !
! active ssh sessions (daemon as such will be started). !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
fi

%post -n openldap-schema-openssh-lpk
%openldap_schema_register %{schemadir}/openssh-lpk.schema
%service -q ldap restart

%postun -n openldap-schema-openssh-lpk
if [ "$1" = "0" ]; then
	%openldap_schema_unregister %{schemadir}/openssh-lpk.schema
	%service -q ldap restart
fi

%files
%defattr(644,root,root,755)
%doc TODO README OVERVIEW CREDITS Change*
%attr(755,root,root) %{_bindir}/ssh-key*
#%attr(755,root,root) %{_bindir}/ssh-vulnkey*
%{_mandir}/man1/ssh-key*.1*
#%{_mandir}/man1/ssh-vulnkey*.1*
%dir %{_sysconfdir}
%dir %{_libexecdir}

%files clients
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/ssh
%attr(755,root,root) %{_bindir}/slogin
%attr(755,root,root) %{_bindir}/sftp
%attr(755,root,root) %{_bindir}/ssh-agent
%attr(755,root,root) %{_bindir}/ssh-add
%attr(755,root,root) %{_bindir}/ssh-copy-id
%attr(755,root,root) %{_bindir}/scp
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/ssh_config
%config(noreplace,missingok) %verify(not md5 mtime size) /etc/env.d/SSH_ASKPASS
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/slogin.1*
%{_mandir}/man1/sftp.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
%{_mandir}/man1/ssh-copy-id.1*
%{_mandir}/man5/ssh_config.5*
%lang(it) %{_mandir}/it/man1/ssh.1*
%lang(it) %{_mandir}/it/man5/ssh_config.5*
%lang(pl) %{_mandir}/pl/man1/scp.1*
%lang(zh_CN) %{_mandir}/zh_CN/man1/scp.1*

# for host-based auth (suid required for accessing private host key)
#%attr(4755,root,root) %{_libexecdir}/ssh-keysign
#%{_mandir}/man8/ssh-keysign.8*

%files clients-agent-profile_d
%defattr(644,root,root,755)
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/ssh-agent.conf
%attr(755,root,root) /etc/profile.d/ssh-agent.sh

%files clients-agent-xinitrc
%defattr(644,root,root,755)
%attr(755,root,root) /etc/X11/xinit/xinitrc.d/ssh-agent.sh

%files server
%defattr(644,root,root,755)
%attr(755,root,root) %{_sbindir}/sshd
%attr(755,root,root) %{_libexecdir}/sftp-server
%attr(755,root,root) %{_libexecdir}/ssh-keysign
%attr(755,root,root) %{_libexecdir}/ssh-pkcs11-helper
%attr(755,root,root) %{_libexecdir}/sshd-keygen
%{_mandir}/man8/sshd.8*
%{_mandir}/man8/sftp-server.8*
%{_mandir}/man8/ssh-keysign.8*
%{_mandir}/man8/ssh-pkcs11-helper.8*
%{_mandir}/man5/sshd_config.5*
%{_mandir}/man5/moduli.5*
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/sshd_config
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/pam.d/sshd
%attr(640,root,root) %{_sysconfdir}/moduli
%attr(754,root,root) /etc/rc.d/init.d/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/sysconfig/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/security/blacklist.sshd
%{systemdunitdir}/sshd.service
%{systemdunitdir}/sshd.socket
%{systemdunitdir}/sshd@.service

%if %{with ldap}
%files server-ldap
%defattr(644,root,root,755)
%doc HOWTO.ldap-keys ldap.conf
%attr(755,root,root) %{_libexecdir}/ssh-ldap-helper
%attr(755,root,root) %{_libexecdir}/ssh-ldap-wrapper
%{_mandir}/man5/ssh-ldap.conf.5*
%{_mandir}/man8/ssh-ldap-helper.8*
%endif

%if %{with gnome} || %{with gtk}
%files gnome-askpass
%defattr(644,root,root,755)
%config(noreplace,missingok) %verify(not md5 mtime size) /etc/env.d/GNOME_SSH_ASKPASS*
%dir %{_libexecdir}/ssh
%attr(755,root,root) %{_libexecdir}/ssh/ssh-askpass
%attr(755,root,root) %{_libexecdir}/ssh-askpass
%endif

%if %{with ldap}
%files -n openldap-schema-openssh-lpk
%defattr(644,root,root,755)
%{schemadir}/openssh-lpk.schema
%endif
