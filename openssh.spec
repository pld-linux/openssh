#
# Conditional build:
%bcond_with	gnome		# with gnome-askpass (GNOME 1.x) utility
%bcond_without	gtk		# without GTK+ (2.x)
%bcond_without	ldap		# with ldap support
%bcond_without	libedit		# without libedit (editline/history support in sftp client)
%bcond_without	kerberos5	# without kerberos5 support
%bcond_without	selinux		# build without SELinux support
%bcond_with	hpn		# High Performance SSH/SCP - HPN-SSH including Cipher NONE (broken too often)

# gtk2-based gnome-askpass means no gnome1-based
%{?with_gtk:%undefine with_gnome}

%if "%{pld_release}" == "ac"
%define		pam_ver	0.79.0
%else
%define		pam_ver	0.99.7.1
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
Version:	5.7p1
Release:	1
Epoch:		2
License:	BSD
Group:		Applications/Networking
Source0:	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
# Source0-md5:	50231fa257219791fa41b84a16c9df04
Source1:	http://www.mif.pg.gda.pl/homepages/ankry/man-PLD/%{name}-non-english-man-pages.tar.bz2
# Source1-md5:	66943d481cc422512b537bcc2c7400d1
Source2:	%{name}d.init
Source3:	%{name}d.pamd
Source4:	%{name}.sysconfig
Source5:	ssh-agent.sh
Source6:	ssh-agent.conf
Source7:	%{name}-lpk.schema
Source8:	%{name}d.upstart
Patch100:	%{name}-heimdal.patch
Patch0:		%{name}-no_libnsl.patch
Patch2:		%{name}-pam_misc.patch
Patch3:		%{name}-sigpipe.patch
# http://code.google.com/p/openssh-lpk/
Patch4:		%{name}-lpk.patch
Patch5:		%{name}-config.patch
# High Performance SSH/SCP - HPN-SSH - http://www.psc.edu/networking/projects/hpn-ssh/
# http://www.psc.edu/networking/projects/hpn-ssh/openssh-5.2p1-hpn13v6.diff.gz
Patch9:		%{name}-5.2p1-hpn13v6.diff
Patch10:	%{name}-include.patch
Patch11:	%{name}-chroot.patch
# http://people.debian.org/~cjwatson/%{name}-blacklist.diff
Patch12:	%{name}-blacklist.diff
URL:		http://www.openssh.com/
BuildRequires:	%{__perl}
BuildRequires:	autoconf
BuildRequires:	automake
%{?with_gnome:BuildRequires:	gnome-libs-devel}
%{?with_gtk:BuildRequires:	gtk+2-devel}
%{?with_kerberos5:BuildRequires:	heimdal-devel >= 0.7}
%{?with_libedit:BuildRequires:	libedit-devel}
%{?with_selinux:BuildRequires:	libselinux-devel}
BuildRequires:	libwrap-devel
%{?with_ldap:BuildRequires:	openldap-devel}
BuildRequires:	openssl-devel >= 0.9.7d
BuildRequires:	pam-devel
%{?with_gtk:BuildRequires:	pkgconfig}
BuildRequires:	rpm >= 4.4.9-56
BuildRequires:	rpmbuild(macros) >= 1.318
BuildRequires:	sed >= 4.0
BuildRequires:	zlib-devel
%if "%{pld_release}" == "ac"
Requires:	filesystem >= 2.0-1
Requires:	pam >= 0.79.0
%else
Requires:	filesystem >= 3.0-11
Requires:	pam >= %{pam_ver}
Suggests:	openssh-blacklist
Suggests:	xorg-app-xauth
%endif
Obsoletes:	ssh
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_sysconfdir	/etc/ssh
%define		_libexecdir	%{_libdir}/%{name}
%define		_privsepdir	/usr/share/empty
%define		schemadir	/usr/share/openldap/schema

## to be moved to rpm-build-macros
## TODO: handle RPM_SKIP_AUTO_RESTART

# migrate from init script to upstart job
%define	upstart_post() \
	if [ -f /var/lock/subsys/"%1" ] ; then \
		/sbin/service --no-upstart "%1" stop \
		/sbin/service "%1" start \
	else \
		/sbin/service "%1" try-restart \
	fi

# restart the job after upgrade or migrate to init script on removal
%define	upstart_postun() \
	if [ -x /sbin/initctl ] && /sbin/initctl status "%1" 2>/dev/null | grep -q 'running' ; then \
		/sbin/initctl stop "%1" 2>/dev/null \
		[ -f "/etc/rc.d/init.d/%1" -o -f "/etc/init/%1.conf" ] && /sbin/service "%1" start \
	fi


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
Requires:	%{name} = %{epoch}:%{version}-%{release}
Requires:	pam >= %{pam_ver}
Requires:	rc-scripts >= 0.4.3.0
Requires:	util-linux
Suggests:	/bin/login
Provides:	ssh-server
Provides:	user(sshd)

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

%package server-upstart
Summary:	Upstart job description for OpenSSH server
Summary(pl.UTF-8):	Opis zadania Upstart dla serwera OpenSSH
Group:		Daemons
Requires:	%{name}-server = %{epoch}:%{version}-%{release}
Requires:	upstart >= 0.6

%description server-upstart
Upstart job description for OpenSSH.

%description server-upstart -l pl.UTF-8
Opis zadania Upstart dla OpenSSH.

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

%description -n openldap-schema-openssh-lpk
This package contains OpenSSH LDAP Public Key schema for openldap.

%description -n openldap-schema-openssh-lpk -l pl.UTF-8
Ten pakiet zawiera schemat klucza publicznego LDAP dla OpenSSH dla
openldap-a.

%prep
%setup -q
%{?with_kerberos5:%patch100 -p1}
%patch0 -p1
%patch2 -p1
%patch3 -p1
%{?with_ldap:%patch4 -p1}
%patch5 -p1
%{?with_hpn:%patch9 -p1}
%patch10 -p1
%patch11 -p1
%patch12 -p1

%if "%{pld_release}" == "ac"
# fix for missing x11.pc
%{__sed} -i -e '/pkg-config/s/ x11//' contrib/Makefile
%endif

%build
cp /usr/share/automake/config.sub .
%{__aclocal}
%{__autoconf}
CPPFLAGS="-DCHROOT"
%configure \
	PERL=%{__perl} \
	--with-pam \
	--with-mantype=man \
	--with-md5-passwords \
	--with-ipaddr-display \
	%{?with_libedit:--with-libedit} \
	--with-4in6 \
	--with-tcp-wrappers \
	%{?with_ldap:--with-libs="-lldap -llber"} \
	%{?with_ldap:--with-cppflags="-DWITH_LDAP_PUBKEY"} \
	%{?with_kerberos5:--with-kerberos5=/usr} \
	--with-privsep-path=%{_privsepdir} \
	--with-pid-dir=%{_localstatedir}/run \
%if "%{pld_release}" == "ac"
	--with-xauth=/usr/X11R6/bin/xauth \
%else
	--with-xauth=%{_bindir}/xauth \
%endif
	--enable-utmpx \
	--enable-wtmpx

echo '#define LOGIN_PROGRAM		   "/bin/login"' >>config.h

%{__make}

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
install -d $RPM_BUILD_ROOT{%{_sysconfdir},/etc/{init,pam.d,rc.d/init.d,sysconfig,security,env.d}} \
	$RPM_BUILD_ROOT{%{_libexecdir}/ssh,%{schemadir}}
install -d $RPM_BUILD_ROOT/etc/{profile.d,X11/xinit/xinitrc.d}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

bzip2 -dc %{SOURCE1} | tar xf - -C $RPM_BUILD_ROOT%{_mandir}

install %{SOURCE2} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install %{SOURCE3} $RPM_BUILD_ROOT/etc/pam.d/sshd
install %{SOURCE4} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install %{SOURCE5} $RPM_BUILD_ROOT/etc/profile.d
ln -sf	/etc/profile.d/ssh-agent.sh $RPM_BUILD_ROOT/etc/X11/xinit/xinitrc.d/ssh-agent.sh
install %{SOURCE6} $RPM_BUILD_ROOT%{_sysconfdir}
install %{SOURCE7} $RPM_BUILD_ROOT%{schemadir}

install %{SOURCE8} $RPM_BUILD_ROOT/etc/init/sshd.conf

%if %{with gnome}
install contrib/gnome-ssh-askpass1 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
%endif
%if %{with gtk}
install contrib/gnome-ssh-askpass2 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
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

install contrib/ssh-copy-id $RPM_BUILD_ROOT%{_bindir}
install contrib/ssh-copy-id.1 $RPM_BUILD_ROOT%{_mandir}/man1

rm -f	$RPM_BUILD_ROOT%{_mandir}/man1/slogin.1
echo ".so ssh.1" > $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1

touch $RPM_BUILD_ROOT/etc/security/blacklist.sshd

cat << 'EOF' > $RPM_BUILD_ROOT/etc/env.d/SSH_ASKPASS
#SSH_ASKPASS="%{_libexecdir}/ssh-askpass"
EOF

rm -f $RPM_BUILD_ROOT%{_datadir}/Ssh.bin # ???
rm -f $RPM_BUILD_ROOT%{_mandir}/README.openssh-non-english-man-pages

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
%service sshd reload "openssh daemon"
if ! grep -qs ssh /etc/security/passwd.conf ; then
	umask 022
	echo "ssh" >> /etc/security/passwd.conf
fi

%preun server
if [ "$1" = "0" ]; then
	%service sshd stop
	/sbin/chkconfig --del sshd
fi

%postun server
if [ "$1" = "0" ]; then
	%userremove sshd
fi

%post server-upstart
%upstart_post sshd

%postun server-upstart
%upstart_postun sshd

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
%doc *.RNG TODO README OVERVIEW CREDITS Change*
%attr(755,root,root) %{_bindir}/ssh-key*
%attr(755,root,root) %{_bindir}/ssh-vulnkey*
%{_mandir}/man1/ssh-key*.1*
%{_mandir}/man1/ssh-vulnkey*.1*
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

%if "%{pld_release}" != "ti"
%files server-upstart
%defattr(644,root,root,755)
%config(noreplace) %verify(not md5 mtime size) /etc/init/sshd.conf
%endif
