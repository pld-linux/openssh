#
# Conditional build:
# _without_gnome - without gnome-askpass utility
#
Summary:	OpenSSH free Secure Shell (SSH) implementation
Summary(es):	ImplementaciСn libre de SSH
Summary(pl):	Publicznie dostЙpna implementacja bezpiecznego shella (SSH)
Summary(pt_BR):	ImplementaГЦo livre do SSH
Summary(ru):	OpenSSH - свободная реализация протокола Secure Shell (SSH)
Summary(uk):	OpenSSH - в╕льна реал╕зац╕я протоколу Secure Shell (SSH)
Name:		openssh
Version:	3.2.3p1
Release:	6
Epoch:		1
License:	BSD
Group:		Applications/Networking
Source0:	ftp://ftp.ca.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
# Source0-md5:	f153ccdb5a91fa06ec78d0c6313f4d77
Source1:	%{name}d.conf
Source2:	%{name}.conf
Source3:	%{name}d.init
Source4:	%{name}d.pamd
Source5:	%{name}.sysconfig
Source6:	passwd.pamd
Patch0:		%{name}-no_libnsl.patch
Patch1:		%{name}-set_12.patch
Patch2:		%{name}-linux-ipv6.patch
Patch3:		%{name}-chall-sec.patch
Patch4:		%{name}-pam-age.patch
Patch5:		%{name}-buffer_c_overflow.patch
Patch6:		%{name}-owl-realloc.patch
# TODO (there are patches for 3.1p1 or 3.4p1... but not 3.2.3p1)
#Patch7:	%{name}-pam-timing.patch
URL:		http://www.openssh.com/
BuildRequires:	XFree86-devel
BuildRequires:	autoconf
BuildRequires:	automake
%{!?_without_gnome:BuildRequires: gnome-libs-devel}
BuildRequires:	libwrap-devel
BuildRequires:	openssl-devel >= 0.9.6a
BuildRequires:	pam-devel
BuildRequires:	perl
BuildRequires:	zlib-devel
PreReq:		openssl
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
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

%description -l es
SSH es un programa para accesar y ejecutar Сrdenes en computadores
remotos. Sustituye rlogin y rsh, y suministra un canal de comunicaciСn
seguro entre dos servidores en una red insegura. Conexiones X11 y
puertas TCP/IP arbitrАrias tambiИn pueden ser usadas por el canal
seguro.

OpenSSH es el resultado del trabajo del equipo de OpenBSD para
continuar la Зltima versiСn gratuita de SSH, actualizАndolo en
tИrminos de seguridad y recursos,asМ tambiИn eliminando todos los
algoritmos patentados y colocАndolos en bibliotecas separadas
(OpenSSL).

Este paquete contiene "port" para Linux de OpenSSH. Se debe instalar
tambiИn el paquete openssh-clients u openssh-server o ambos.

%description -l pl
Ssh (Secure Shell) to program sЁu©╠cy do logowania siЙ na zdaln╠
maszynЙ i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast╠piФ rlogin, rsh i dostarczyФ bezpieczne, szyfrowane poЁ╠czenie
pomiedzy dwoma hostami.

%description -l pt_BR
SSH И um programa para acessar e executar comandos em mАquinas
remotas. Ele substitui rlogin e rsh, e provem um canal de comunicaГЦo
seguro entre dois hosts em uma rede insegura. ConexУes X11 e portas
TCP/IP arbitrАrias tambИm podem ser usadas pelo canal seguro.

OpenSSH И o resultado do trabalho da equipe do OpenBSD em continuar a
Зltima versЦo gratuita do SSH, atualizando-o em termos de seguranГa e
recursos, assim como removendo todos os algoritmos patenteados e
colocando-os em bibliotecas separadas (OpenSSL).

Esse pacote contИm o "port" pra Linux do OpenSSH. VocЙ deve instalar
tambИm ou o pacote openssh-clients, ou o openssh-server, ou ambos.

%description -l ru
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

%description -l uk
Ssh (Secure Shell) - це програма для "заходу" (login) до в╕ддалено╖
машини та для виконання команд на в╕ддален╕й машин╕. Вона призначена
для зам╕ни rlogin та rsh ╕ забезпечу╓ безпечну шифровану комун╕кац╕ю
м╕ж двома хостами в мереж╕, яка не ╓ безпечною. З'╓днання X11 та
дов╕льн╕ порти TCP/IP можуть також бути проведен╕ через безпечний
канал.

OpenSSH - це переробка командою розробник╕в OpenBSD останньо╖ в╕льно╖
верс╕╖ SSH, доведена до сучасного стану в терм╕нах р╕вня безпеки та
п╕дтримуваних можливостей. Вс╕ патентован╕ алгоритми винесен╕ до
окремих б╕бл╕отек (OpenSSL).

Цей пакет м╕стить файли, необх╕дн╕ як для кл╕╓нта, так ╕ для сервера
OpenSSH. Вам потр╕бно буде ще встановити openssh-clients,
openssh-server, чи обидва пакети.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Summary(es):	Clientes de OpenSSH
Summary(pl):	Klienci protokoЁu Secure Shell
Summary(pt_BR):	Clientes do OpenSSH
Summary(ru):	OpenSSH - клиенты протокола Secure Shell
Summary(uk):	OpenSSH - кл╕╓нти протоколу Secure Shell
Group:		Applications/Networking
Requires:	%{name} = %{version}
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

%description clients -l es
Este paquete incluye los clientes que se necesitan para hacer
conexiones codificadas con servidores SSH.

%description clients -l pl
Ssh (Secure Shell) to program sЁu©╠cy do logowania siЙ na zdaln╠
maszynЙ i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast╠piФ rlogin, rsh i dostarczyФ bezpieczne, szyfrowane poЁ╠czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera klientСw sЁu©╠cych do Ё╠czenia siЙ z serwerami SSH.

%description clients -l pt_BR
Esse pacote inclui os clientes necessАrios para fazer conexУes
encriptadas com servidores SSH.

%description clients -l ru
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит программы-клиенты, необходимые для установления
зашифрованных соединений с серверами SSH.

%description clients -l uk
Ssh (Secure Shell) - це програма для "заходу" (login) до в╕ддалено╖
машини та для виконання команд на в╕ддален╕й машин╕.

Цей пакет м╕стить програми-кл╕╓нти, необх╕дн╕ для встановлення
зашифрованих з'╓днань з серверами SSH.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Summary(es):	Servidor OpenSSH para comunicaciones codificadas
Summary(pl):	Serwer protokoЁu Secure Shell (sshd)
Summary(pt_BR):	Servidor OpenSSH para comunicaГУes encriptadas
Summary(ru):	OpenSSH - сервер протокола Secure Shell (sshd)
Summary(uk):	OpenSSH - сервер протоколу Secure Shell (sshd)
Group:		Networking/Daemons
PreReq:		rc-scripts
PreReq:		/sbin/chkconfig
PreReq:		%{name} = %{version}
Requires:	/bin/login
Requires:	util-linux
Obsoletes:	ssh-server

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
Ssh (Secure Shell) to program sЁu©╠cy do logowania siЙ na zdaln╠
maszynЙ i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast╠piФ rlogin, rsh i dostarczyФ bezpieczne, szyfrowane poЁ╠czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera serwer sshd (do ktСrego mog╠ Ё╠czyФ siЙ klienci
ssh).

%description server -l pt_BR
Esse pacote contИm o servidor SSH. O sshd И a parte servidor do
protocolo secure shell e permite que clientes ssh se conectem ao seu
host.

%description server -l ru
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит sshd - "демон" Secure Shell. sshd - это серверная
часть протокола Secure Shell, позволяющая клиентам ssh соединяться с
вашим хостом.

%description server -l uk
Ssh (Secure Shell) - це програма для "заходу" (login) до в╕ддалено╖
машини та для виконання команд на в╕ддален╕й машин╕.

Цей пакет м╕стить sshd - "демон" Secure Shell. sshd - це серверна
частина протоколу Secure Shell, яка дозволя╓ кл╕╓нтам ssh зв'язуватись
з вашим хостом.

%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Summary(es):	DiАlogo para introducciСn de passphrase para GNOME
Summary(pl):	Odpytywacz hasЁa OpenSSH dla GNOME
Summary(pt_BR):	DiАlogo para entrada de passphrase para GNOME
Summary(ru):	OpenSSH - диалог ввода ключевой фразы (passphrase) для GNOME
Summary(uk):	OpenSSH - д╕алог вводу ключово╖ фрази (passphrase) для GNOME
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
Este paquete contiene un programa que abre una caja de diАlogo para
entrada de passphrase en GNOME.

%description gnome-askpass -l pl
Ssh (Secure Shell) to program sЁu©╠cy do logowania siЙ na zdaln╠
maszynЙ i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast╠piФ rlogin, rsh i dostarczyФ bezpieczne, szyfrowane poЁ╠czenie
pomiedzy dwoma hostami.

Ten pakiet zawiera ,,odpytywacz hasЁa'' dla GNOME.

%description gnome-askpass -l pt_BR
Esse pacote contИm um programa que abre uma caixa de diАlogo para
entrada de passphrase no GNOME.

%description gnome-askpass -l ru
Ssh (Secure Shell) - это программа для "захода" (login) на удаленную
машину и для выполнения команд на удаленной машине.

Этот пакет содержит диалог ввода ключевой фразы для использования под
GNOME.

%description gnome-askpass -l uk
Ssh (Secure Shell) - це програма для "заходу" (login) до в╕ддалено╖
машини та для виконання команд на в╕ддален╕й машин╕.

Цей пакет м╕стить д╕алог вводу ключово╖ фрази для використання п╕д
GNOME.

%prep
%setup  -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
#%patch7 -p1

%build
%{__aclocal}
%{__autoconf}

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
%{!?_without_gnome:gnome-ssh-askpass.c -o gnome-ssh-askpass } \
%{!?_without_gnome:`gnome-config --libs gnome gnomeui gtk` }

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_sysconfdir},/etc/{pam.d,rc.d/init.d,sysconfig,security}}

%{__make} install \
	DESTDIR="$RPM_BUILD_ROOT"

install %{SOURCE4} $RPM_BUILD_ROOT/etc/pam.d/sshd
install %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/passwdssh
install %{SOURCE5} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/ssh_config
install %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/sshd_config
install -d $RPM_BUILD_ROOT%{_libexecdir}/ssh
%{!?_without_gnome:install contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/ssh-askpass}

rm -f	$RPM_BUILD_ROOT%{_mandir}/man1/slogin.1
echo ".so ssh.1" > $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1

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
%doc *.RNG TODO README OVERVIEW CREDITS Change*
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
%{!?_without_gnome:%attr(755,root,root) %{_libexecdir}/ssh-askpass}
