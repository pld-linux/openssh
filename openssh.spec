#
# Conditional build:
%bcond_without	chroot		# without chrooted user environment support
%bcond_with	gnome		# with gnome-askpass (GNOME 1.x) utility
%bcond_without	gtk		# without GTK+ (2.x)
%bcond_with	ldap		# with ldap support
%bcond_without	libedit		# without libedit (editline/history support in sftp client)
%bcond_without	kerberos5	# without kerberos5 support
%bcond_without	selinux		# build without SELinux support
%bcond_with	sshagentsh	# with system-wide script for starting ssh-agent
#
# gtk2-based gnome-askpass means no gnome1-based
%{?with_gtk:%undefine with_gnome}
Summary:	OpenSSH free Secure Shell (SSH) implementation
Summary(de):	OpenSSH - freie Implementation der Secure Shell (SSH)
Summary(es):	Implementación libre de SSH
Summary(fr):	Implémentation libre du shell sécurisé OpenSSH (SSH)
Summary(it):	Implementazione gratuita OpenSSH della Secure Shell
Summary(pl):	Publicznie dostêpna implementacja bezpiecznego shella (SSH)
Summary(pt):	Implementação livre OpenSSH do protocolo 'Secure Shell' (SSH)
Summary(pt_BR):	Implementação livre do SSH
Summary(ru):	OpenSSH - Ó×ÏÂÏÄÎÁÑ ÒÅÁÌÉÚÁÃÉÑ ÐÒÏÔÏËÏÌÁ Secure Shell (SSH)
Summary(uk):	OpenSSH - ×¦ÌØÎÁ ÒÅÁÌ¦ÚÁÃ¦Ñ ÐÒÏÔÏËÏÌÕ Secure Shell (SSH)
Name:		openssh
Version:	4.0p1
Release:	0.1
Epoch:		2
License:	BSD
Group:		Applications/Networking
Source0:	ftp://ftp.ca.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
# Source0-md5:	7b36f28fc16e1b7f4ba3c1dca191ac92
Source1:	%{name}d.conf
Source2:	%{name}.conf
Source3:	%{name}d.init
Source4:	%{name}d.pamd
Source5:	%{name}.sysconfig
Source6:	passwd.pamd
Source7:	http://www.mif.pg.gda.pl/homepages/ankry/man-PLD/openssh-non-english-man-pages.tar.bz2
# Source7-md5:	66943d481cc422512b537bcc2c7400d1
Source9:	http://www.imasy.or.jp/~gotoh/ssh/connect.c
# NoSource9-md5:	c78de727e1208799072be78c05d64398
Source10:	http://www.imasy.or.jp/~gotoh/ssh/connect.html
# NoSource10-md5:	f14cb61fafd067a3f5ce4eaa9643bf05
Source11:	ssh-agent.sh
Source12:	ssh-agent.conf
Patch0:		%{name}-no_libnsl.patch
Patch2:		%{name}-linux-ipv6.patch
Patch3:		%{name}-pam_misc.patch
Patch4:		%{name}-sigpipe.patch
# http://ldappubkey.gcu-squad.org/
Patch5:		ldappubkey-ossh3.6-v2.patch
Patch6:		%{name}-heimdal.patch
Patch7:		%{name}-pam-conv.patch
# http://chrootssh.sourceforge.net/download/osshChroot-3.7.1p2.diff
Patch8:		%{name}-chroot.patch
Patch9:		%{name}-selinux.patch
Patch10:	%{name}-selinux-pld.patch
URL:		http://www.openssh.com/
BuildRequires:	autoconf
BuildRequires:	automake
%{?with_gnome:BuildRequires:	gnome-libs-devel}
%{?with_gtk:BuildRequires:	gtk+2-devel}
%{?with_kerberos5:BuildRequires:	heimdal-devel}
%{?with_libedit:BuildRequires:	libedit-devel}
%{?with_selinux:BuildRequires:	libselinux-devel}
BuildRequires:	libwrap-devel
%{?with_ldap:BuildRequires:	openldap-devel}
BuildRequires:	openssl-devel >= 0.9.7d
BuildRequires:	pam-devel
BuildRequires:	%{__perl}
%{?with_gtk:BuildRequires:	pkgconfig}
BuildRequires:	rpmbuild(macros) >= 1.159
BuildRequires:	zlib-devel
PreReq:		FHS >= 2.1-24
PreReq:		openssl >= 0.9.7d
Obsoletes:	ssh
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_sysconfdir	/etc/ssh
%define		_libexecdir	%{_libdir}/%{name}
%define		_privsepdir	/usr/share/empty

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

%description -l de
OpenSSH (Secure Shell) stellt den Zugang zu anderen Rechnern her. Es
ersetzt telnet, rlogin, rexec und rsh und stellt eine sichere,
verschlüsselte Verbindung zwischen zwei nicht vertrauenswürdigen Hosts
über eine unsicheres Netzwerk her. X11 Verbindungen und beliebige
andere TCP/IP Ports können ebenso über den sicheren Channel
weitergeleitet werden.

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

%description -l fr
OpenSSH (Secure Shell) fournit un accès à un système distant. Il
remplace telnet, rlogin, rexec et rsh, tout en assurant des
communications cryptées securisées entre deux hôtes non fiabilisés sur
un réseau non sécurisé. Des connexions X11 et des ports TCP/IP
arbitraires peuvent également être transmis sur le canal sécurisé.

%description -l it
OpenSSH (Secure Shell) fornisce l'accesso ad un sistema remoto.
Sostituisce telnet, rlogin, rexec, e rsh, e fornisce comunicazioni
sicure e crittate tra due host non fidati su una rete non sicura. Le
connessioni X11 ad una porta TCP/IP arbitraria possono essere
inoltrate attraverso un canale sicuro.

%description -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiêdzy dwoma hostami.

Ten pakiet zawiera podstawowe pliki potrzebne zarówno po stronie
klienta jak i serwera OpenSSH. Aby by³ u¿yteczny, trzeba zainstalowaæ
co najmniej jeden z pakietów: openssh-clients lub openssh-server.

%description -l pt
OpenSSH (Secure Shell) fornece acesso a um sistema remoto. Substitui o
telnet, rlogin, rexec, e o rsh e fornece comunicações seguras e
cifradas entre duas máquinas sem confiança mútua sobre uma rede
insegura. Ligações X11 e portos TCP/IP arbitrários também poder ser
reenviados pelo canal seguro.

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

%description -l ru
Ssh (Secure Shell) - ÜÔÏ ÐÒÏÇÒÁÍÍÁ ÄÌÑ "ÚÁÈÏÄÁ" (login) ÎÁ ÕÄÁÌÅÎÎÕÀ
ÍÁÛÉÎÕ É ÄÌÑ ×ÙÐÏÌÎÅÎÉÑ ËÏÍÁÎÄ ÎÁ ÕÄÁÌÅÎÎÏÊ ÍÁÛÉÎÅ. ïÎÁ ÐÒÅÄÎÁÚÎÁÞÅÎÁ
ÄÌÑ ÚÁÍÅÎÙ rlogin É rsh É ÏÂÅÓÐÅÞÉ×ÁÅÔ ÂÅÚÏÐÁÓÎÕÀ ÛÉÆÒÏ×ÁÎÎÕÀ
ËÏÍÍÕÎÉËÁÃÉÀ ÍÅÖÄÕ Ä×ÕÍÑ ÈÏÓÔÁÍÉ × ÓÅÔÉ, Ñ×ÌÑÀÝÅÊÓÑ ÎÅÂÅÚÏÐÁÓÎÏÊ.
óÏÅÄÉÎÅÎÉÑ X11 É ÌÀÂÙÅ ÐÏÒÔÙ TCP/IP ÍÏÇÕÔ ÔÁËÖÅ ÂÙÔØ ÐÒÏ×ÅÄÅÎÙ ÞÅÒÅÚ
ÂÅÚÏÐÁÓÎÙÊ ËÁÎÁÌ.

OpenSSH - ÜÔÏ ÐÅÒÅÄÅÌËÁ ËÏÍÁÎÄÏÊ ÒÁÚÒÁÂÏÔÞÉËÏ× OpenBSD ÐÏÓÌÅÄÎÅÊ
Ó×ÏÂÏÄÎÏÊ ×ÅÒÓÉÉ SSH, ÄÏ×ÅÄÅÎÎÁÑ ÄÏ ÓÏ×ÒÅÍÅÎÎÏÇÏ ÓÏÓÔÏÑÎÉÑ × ÔÅÒÍÉÎÁÈ
ÕÒÏ×ÎÑ ÂÅÚÏÐÁÓÎÏÓÔÉ É ÐÏÄÄÅÒÖÉ×ÁÅÍÙÈ ×ÏÚÍÏÖÎÏÓÔÅÊ. ÷ÓÅ ÐÁÔÅÎÔÏ×ÁÎÎÙÅ
ÁÌÇÏÒÉÔÍÙ ×ÙÎÅÓÅÎÙ × ÏÔÄÅÌØÎÙÅ ÂÉÂÌÉÏÔÅËÉ (OpenSSL).

üÔÏÔ ÐÁËÅÔ ÓÏÄÅÒÖÉÔ ÆÁÊÌÙ, ÎÅÏÂÈÏÄÉÍÙÅ ËÁË ÄÌÑ ËÌÉÅÎÔÁ, ÔÁË É ÄÌÑ
ÓÅÒ×ÅÒÁ OpenSSH. ÷ÁÍ ÎÕÖÎÏ ÂÕÄÅÔ ÕÓÔÁÎÏ×ÉÔØ ÅÝÅ openssh-clients,
openssh-server, ÉÌÉ ÏÂÁ ÐÁËÅÔÁ.

%description -l uk
Ssh (Secure Shell) - ÃÅ ÐÒÏÇÒÁÍÁ ÄÌÑ "ÚÁÈÏÄÕ" (login) ÄÏ ×¦ÄÄÁÌÅÎÏ§
ÍÁÛÉÎÉ ÔÁ ÄÌÑ ×ÉËÏÎÁÎÎÑ ËÏÍÁÎÄ ÎÁ ×¦ÄÄÁÌÅÎ¦Ê ÍÁÛÉÎ¦. ÷ÏÎÁ ÐÒÉÚÎÁÞÅÎÁ
ÄÌÑ ÚÁÍ¦ÎÉ rlogin ÔÁ rsh ¦ ÚÁÂÅÚÐÅÞÕ¤ ÂÅÚÐÅÞÎÕ ÛÉÆÒÏ×ÁÎÕ ËÏÍÕÎ¦ËÁÃ¦À
Í¦Ö Ä×ÏÍÁ ÈÏÓÔÁÍÉ × ÍÅÒÅÖ¦, ÑËÁ ÎÅ ¤ ÂÅÚÐÅÞÎÏÀ. ú'¤ÄÎÁÎÎÑ X11 ÔÁ
ÄÏ×¦ÌØÎ¦ ÐÏÒÔÉ TCP/IP ÍÏÖÕÔØ ÔÁËÏÖ ÂÕÔÉ ÐÒÏ×ÅÄÅÎ¦ ÞÅÒÅÚ ÂÅÚÐÅÞÎÉÊ
ËÁÎÁÌ.

OpenSSH - ÃÅ ÐÅÒÅÒÏÂËÁ ËÏÍÁÎÄÏÀ ÒÏÚÒÏÂÎÉË¦× OpenBSD ÏÓÔÁÎÎØÏ§ ×¦ÌØÎÏ§
×ÅÒÓ¦§ SSH, ÄÏ×ÅÄÅÎÁ ÄÏ ÓÕÞÁÓÎÏÇÏ ÓÔÁÎÕ × ÔÅÒÍ¦ÎÁÈ Ò¦×ÎÑ ÂÅÚÐÅËÉ ÔÁ
Ð¦ÄÔÒÉÍÕ×ÁÎÉÈ ÍÏÖÌÉ×ÏÓÔÅÊ. ÷Ó¦ ÐÁÔÅÎÔÏ×ÁÎ¦ ÁÌÇÏÒÉÔÍÉ ×ÉÎÅÓÅÎ¦ ÄÏ
ÏËÒÅÍÉÈ Â¦ÂÌ¦ÏÔÅË (OpenSSL).

ãÅÊ ÐÁËÅÔ Í¦ÓÔÉÔØ ÆÁÊÌÉ, ÎÅÏÂÈ¦ÄÎ¦ ÑË ÄÌÑ ËÌ¦¤ÎÔÁ, ÔÁË ¦ ÄÌÑ ÓÅÒ×ÅÒÁ
OpenSSH. ÷ÁÍ ÐÏÔÒ¦ÂÎÏ ÂÕÄÅ ÝÅ ×ÓÔÁÎÏ×ÉÔÉ openssh-clients,
openssh-server, ÞÉ ÏÂÉÄ×Á ÐÁËÅÔÉ.

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Summary(es):	Clientes de OpenSSH
Summary(pl):	Klienci protoko³u Secure Shell
Summary(pt_BR):	Clientes do OpenSSH
Summary(ru):	OpenSSH - ËÌÉÅÎÔÙ ÐÒÏÔÏËÏÌÁ Secure Shell
Summary(uk):	OpenSSH - ËÌ¦¤ÎÔÉ ÐÒÏÔÏËÏÌÕ Secure Shell
Group:		Applications/Networking
Requires:	%{name} = %{epoch}:%{version}-%{release}
%{?with_sshagentsh:Requires:	xinitrc}
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

%description clients -l es
Este paquete incluye los clientes que se necesitan para hacer
conexiones codificadas con servidores SSH.

%description clients -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiêdzy dwoma hostami.

Ten pakiet zawiera klientów s³u¿±cych do ³±czenia siê z serwerami SSH.

%description clients -l pt_BR
Esse pacote inclui os clientes necessários para fazer conexões
encriptadas com servidores SSH.

%description clients -l ru
Ssh (Secure Shell) - ÜÔÏ ÐÒÏÇÒÁÍÍÁ ÄÌÑ "ÚÁÈÏÄÁ" (login) ÎÁ ÕÄÁÌÅÎÎÕÀ
ÍÁÛÉÎÕ É ÄÌÑ ×ÙÐÏÌÎÅÎÉÑ ËÏÍÁÎÄ ÎÁ ÕÄÁÌÅÎÎÏÊ ÍÁÛÉÎÅ.

üÔÏÔ ÐÁËÅÔ ÓÏÄÅÒÖÉÔ ÐÒÏÇÒÁÍÍÙ-ËÌÉÅÎÔÙ, ÎÅÏÂÈÏÄÉÍÙÅ ÄÌÑ ÕÓÔÁÎÏ×ÌÅÎÉÑ
ÚÁÛÉÆÒÏ×ÁÎÎÙÈ ÓÏÅÄÉÎÅÎÉÊ Ó ÓÅÒ×ÅÒÁÍÉ SSH.

%description clients -l uk
Ssh (Secure Shell) - ÃÅ ÐÒÏÇÒÁÍÁ ÄÌÑ "ÚÁÈÏÄÕ" (login) ÄÏ ×¦ÄÄÁÌÅÎÏ§
ÍÁÛÉÎÉ ÔÁ ÄÌÑ ×ÉËÏÎÁÎÎÑ ËÏÍÁÎÄ ÎÁ ×¦ÄÄÁÌÅÎ¦Ê ÍÁÛÉÎ¦.

ãÅÊ ÐÁËÅÔ Í¦ÓÔÉÔØ ÐÒÏÇÒÁÍÉ-ËÌ¦¤ÎÔÉ, ÎÅÏÂÈ¦ÄÎ¦ ÄÌÑ ×ÓÔÁÎÏ×ÌÅÎÎÑ
ÚÁÛÉÆÒÏ×ÁÎÉÈ Ú'¤ÄÎÁÎØ Ú ÓÅÒ×ÅÒÁÍÉ SSH.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Summary(de):	OpenSSH Secure Shell Protocol-Server (sshd)
Summary(es):	Servidor OpenSSH para comunicaciones codificadas
Summary(fr):	Serveur de protocole du shell sécurisé OpenSSH (sshd)
Summary(it):	Server OpenSSH per il protocollo Secure Shell (sshd)
Summary(pl):	Serwer protoko³u Secure Shell (sshd)
Summary(pt):	Servidor do protocolo 'Secure Shell' OpenSSH (sshd)
Summary(pt_BR):	Servidor OpenSSH para comunicações encriptadas
Summary(ru):	OpenSSH - ÓÅÒ×ÅÒ ÐÒÏÔÏËÏÌÁ Secure Shell (sshd)
Summary(uk):	OpenSSH - ÓÅÒ×ÅÒ ÐÒÏÔÏËÏÌÕ Secure Shell (sshd)
Group:		Networking/Daemons
PreReq:		%{name} = %{epoch}:%{version}-%{release}
PreReq:		rc-scripts >= 0.3.1-15
Requires(pre):	/bin/id
Requires(pre):	/usr/sbin/useradd
Requires(post,preun):	/sbin/chkconfig
Requires(post):	chkconfig >= 0.9
Requires(post):	grep
Requires(postun):	/usr/sbin/userdel
Requires:	/bin/login
Requires:	util-linux
Requires:	pam >= 0.77.3
Provides:	user(sshd)
Provides:	ssh-server

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

%description server -l de
Dieses Paket installiert den sshd, den Server-Teil der OpenSSH.

%description server -l es
Este paquete contiene el servidor SSH. sshd es la parte servidor del
protocolo secure shell y permite que clientes ssh se conecten a su
servidor.

%description server -l fr
Ce paquetage installe le 'sshd', partie serveur de OpenSSH.

%description server -l it
Questo pacchetto installa sshd, il server di OpenSSH.

%description server -l pl
Ssh (Secure Shell) to program s³u¿±cy do logowania siê na zdaln±
maszynê i uruchamiania na niej aplikacji. W zamierzeniu openssh ma
zast±piæ rlogin, rsh i dostarczyæ bezpieczne, szyfrowane po³±czenie
pomiêdzy dwoma hostami.

Ten pakiet zawiera serwer sshd (do którego mog± ³±czyæ siê klienci
ssh).

%description server -l pt
Este pacote intala o sshd, o servidor do OpenSSH.

%description server -l pt_BR
Esse pacote contém o servidor SSH. O sshd é a parte servidor do
protocolo secure shell e permite que clientes ssh se conectem ao seu
host.

%description server -l ru
Ssh (Secure Shell) - ÜÔÏ ÐÒÏÇÒÁÍÍÁ ÄÌÑ "ÚÁÈÏÄÁ" (login) ÎÁ ÕÄÁÌÅÎÎÕÀ
ÍÁÛÉÎÕ É ÄÌÑ ×ÙÐÏÌÎÅÎÉÑ ËÏÍÁÎÄ ÎÁ ÕÄÁÌÅÎÎÏÊ ÍÁÛÉÎÅ.

üÔÏÔ ÐÁËÅÔ ÓÏÄÅÒÖÉÔ sshd - "ÄÅÍÏÎ" Secure Shell. sshd - ÜÔÏ ÓÅÒ×ÅÒÎÁÑ
ÞÁÓÔØ ÐÒÏÔÏËÏÌÁ Secure Shell, ÐÏÚ×ÏÌÑÀÝÁÑ ËÌÉÅÎÔÁÍ ssh ÓÏÅÄÉÎÑÔØÓÑ Ó
×ÁÛÉÍ ÈÏÓÔÏÍ.

%description server -l uk
Ssh (Secure Shell) - ÃÅ ÐÒÏÇÒÁÍÁ ÄÌÑ "ÚÁÈÏÄÕ" (login) ÄÏ ×¦ÄÄÁÌÅÎÏ§
ÍÁÛÉÎÉ ÔÁ ÄÌÑ ×ÉËÏÎÁÎÎÑ ËÏÍÁÎÄ ÎÁ ×¦ÄÄÁÌÅÎ¦Ê ÍÁÛÉÎ¦.

ãÅÊ ÐÁËÅÔ Í¦ÓÔÉÔØ sshd - "ÄÅÍÏÎ" Secure Shell. sshd - ÃÅ ÓÅÒ×ÅÒÎÁ
ÞÁÓÔÉÎÁ ÐÒÏÔÏËÏÌÕ Secure Shell, ÑËÁ ÄÏÚ×ÏÌÑ¤ ËÌ¦¤ÎÔÁÍ ssh Ú×'ÑÚÕ×ÁÔÉÓØ
Ú ×ÁÛÉÍ ÈÏÓÔÏÍ.

%package gnome-askpass
Summary:	OpenSSH GNOME passphrase dialog
Summary(de):	OpenSSH GNOME Passwort-Dialog
Summary(es):	Diálogo para introducción de passphrase para GNOME
Summary(fr):	Dialogue pass-phrase GNOME d'OpenSSH
Summary(it):	Finestra di dialogo GNOME per la frase segreta di OpenSSH
Summary(pl):	Odpytywacz has³a OpenSSH dla GNOME
Summary(pt):	Diálogo de pedido de senha para GNOME do OpenSSH
Summary(pt_BR):	Diálogo para entrada de passphrase para GNOME
Summary(ru):	OpenSSH - ÄÉÁÌÏÇ ××ÏÄÁ ËÌÀÞÅ×ÏÊ ÆÒÁÚÙ (passphrase) ÄÌÑ GNOME
Summary(uk):	OpenSSH - Ä¦ÁÌÏÇ ××ÏÄÕ ËÌÀÞÏ×Ï§ ÆÒÁÚÉ (passphrase) ÄÌÑ GNOME
Group:		Applications/Networking
Requires:	%{name} = %{epoch}:%{version}-%{release}
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
pomiêdzy dwoma hostami.

Ten pakiet zawiera ,,odpytywacz has³a'' dla GNOME.

%description gnome-askpass -l pt_BR
Esse pacote contém um programa que abre uma caixa de diálogo para
entrada de passphrase no GNOME.

%description gnome-askpass -l ru
Ssh (Secure Shell) - ÜÔÏ ÐÒÏÇÒÁÍÍÁ ÄÌÑ "ÚÁÈÏÄÁ" (login) ÎÁ ÕÄÁÌÅÎÎÕÀ
ÍÁÛÉÎÕ É ÄÌÑ ×ÙÐÏÌÎÅÎÉÑ ËÏÍÁÎÄ ÎÁ ÕÄÁÌÅÎÎÏÊ ÍÁÛÉÎÅ.

üÔÏÔ ÐÁËÅÔ ÓÏÄÅÒÖÉÔ ÄÉÁÌÏÇ ××ÏÄÁ ËÌÀÞÅ×ÏÊ ÆÒÁÚÙ ÄÌÑ ÉÓÐÏÌØÚÏ×ÁÎÉÑ ÐÏÄ
GNOME.

%description gnome-askpass -l uk
Ssh (Secure Shell) - ÃÅ ÐÒÏÇÒÁÍÁ ÄÌÑ "ÚÁÈÏÄÕ" (login) ÄÏ ×¦ÄÄÁÌÅÎÏ§
ÍÁÛÉÎÉ ÔÁ ÄÌÑ ×ÉËÏÎÁÎÎÑ ËÏÍÁÎÄ ÎÁ ×¦ÄÄÁÌÅÎ¦Ê ÍÁÛÉÎ¦.

ãÅÊ ÐÁËÅÔ Í¦ÓÔÉÔØ Ä¦ÁÌÏÇ ××ÏÄÕ ËÌÀÞÏ×Ï§ ÆÒÁÚÉ ÄÌÑ ×ÉËÏÒÉÓÔÁÎÎÑ Ð¦Ä
GNOME.

%prep
%setup -q
%patch0 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%{?with_ldap:%patch5 -p1}
%{?with_kerberos5:%patch6 -p1}
#%patch7 -p1
%patch8 -p1
%{?with_selinux:%patch9 -p1}
%{?with_selinux:%patch10 -p1}

%build
cp %{_datadir}/automake/config.sub .
%{__aclocal}
%{__autoconf}
%{?with_chroot:CPPFLAGS="-DCHROOT"}
%configure \
	PERL=%{__perl} \
	--with-dns \
	--with-pam \
	--with-mantype=man \
	--with-md5-passwords \
	--with-ipaddr-display \
	%{?with_libedit:--with-libedit} \
	--with-4in6 \
	--disable-suid-ssh \
	--with-tcp-wrappers \
	%{?with_ldap:--with-libs="-lldap -llber"} \
	%{?with_ldap:--with-cppflags="-DWITH_LDAP_PUBKEY"} \
	%{?with_kerberos5:--with-kerberos5} \
	--with-privsep-path=%{_privsepdir} \
	--with-pid-dir=%{_localstatedir}/run \
	--with-xauth=/usr/X11R6/bin/xauth

echo '#define LOGIN_PROGRAM           "/bin/login"' >>config.h

%{__make}

cp -f %{SOURCE9} .
cp -f %{SOURCE10} .
%{__cc} %{rpmcflags} %{rpmldflags} connect.c -o connect

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
	$RPM_BUILD_ROOT%{_libexecdir}/ssh
%{?with_sshagentsh:install -d $RPM_BUILD_ROOT/etc/{profile.d,X11/xinit/xinitrc.d}}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install connect    $RPM_BUILD_ROOT%{_bindir}
install %{SOURCE4} $RPM_BUILD_ROOT/etc/pam.d/sshd
install %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/passwdssh
install %{SOURCE5} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/ssh_config
install %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/sshd_config
%if %{with sshagentsh}
install %{SOURCE11} $RPM_BUILD_ROOT/etc/profile.d/
ln -sf	/etc/profile.d/ssh-agent.sh $RPM_BUILD_ROOT/etc/X11/xinit/xinitrc.d/ssh-agent.sh
install %{SOURCE12} $RPM_BUILD_ROOT/etc/ssh/
%endif

bzip2 -dc %{SOURCE7} | tar xf - -C $RPM_BUILD_ROOT%{_mandir}

%if %{with gnome}
install contrib/gnome-ssh-askpass1 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
%endif
%if %{with gtk}
install contrib/gnome-ssh-askpass2 $RPM_BUILD_ROOT%{_libexecdir}/ssh/ssh-askpass
%endif
%if %{with gnome} || %{with gtk}
cat << EOF >$RPM_BUILD_ROOT/etc/env.d/GNOME_SSH_ASKPASS_GRAB_SERVER
#GNOME_SSH_ASKPASS_GRAB_SERVER="true"
EOF
cat << EOF >$RPM_BUILD_ROOT/etc/env.d/GNOME_SSH_ASKPASS_GRAB_POINTER
#GNOME_SSH_ASKPASS_GRAB_POINTER="true"
EOF
ln -s %{_libexecdir}/ssh/ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/ssh-askpass
%endif

rm -f	$RPM_BUILD_ROOT%{_mandir}/man1/slogin.1
echo ".so ssh.1" > $RPM_BUILD_ROOT%{_mandir}/man1/slogin.1

touch $RPM_BUILD_ROOT/etc/security/blacklist.sshd

cat << EOF >$RPM_BUILD_ROOT/etc/env.d/SSH_ASKPASS
#SSH_ASKPASS="%{_libexecdir}/ssh-askpass"
EOF

%clean
rm -rf $RPM_BUILD_ROOT

%pre server
if [ -n "`/bin/id -u sshd 2>/dev/null`" ]; then
	if [ "`/bin/id -u sshd`" != "40" ]; then
		echo "Error: user sshd doesn't have uid=40. Correct this before installing ssh server." 1>&2
		exit 1
	fi
else
	/usr/sbin/useradd -u 40 -d %{_privsepdir} -s /bin/false -c "OpenSSH PrivSep User" -g nobody sshd 1>&2
fi

%post server
/sbin/chkconfig --add sshd
if [ -f /var/lock/subsys/sshd ]; then
	/etc/rc.d/init.d/sshd restart 1>&2
else
	echo "Run \"/etc/rc.d/init.d/sshd start\" to start openssh daemon."
fi
if ! grep -qs ssh /etc/security/passwd.conf ; then
	umask 022
	echo "ssh" >> /etc/security/passwd.conf
fi

%preun server
if [ "$1" = "0" ]; then
	if [ -f /var/lock/subsys/sshd ]; then
		/etc/rc.d/init.d/sshd stop 1>&2
	fi
	/sbin/chkconfig --del sshd
fi

%postun server
if [ "$1" = "0" ]; then
	%userremove sshd
fi

%files
%defattr(644,root,root,755)
%doc *.RNG TODO README OVERVIEW CREDITS Change*
%attr(755,root,root) %{_bindir}/ssh-key*
%{_mandir}/man1/ssh-key*.1*
%dir %{_sysconfdir}
%dir %{_libexecdir}

%files clients
%defattr(644,root,root,755)
%doc connect.html
%attr(755,root,root) %{_bindir}/connect
%attr(755,root,root) %{_bindir}/ssh
%attr(755,root,root) %{_bindir}/slogin
%attr(755,root,root) %{_bindir}/sftp
%attr(755,root,root) %{_bindir}/ssh-agent
%attr(755,root,root) %{_bindir}/ssh-add
%attr(755,root,root) %{_bindir}/scp
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/ssh_config
%attr(644,root,root) %config(noreplace,missingok) %verify(not md5 size mtime) /etc/env.d/SSH_ASKPASS
%if %{with sshagentsh}
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/ssh-agent.conf
%attr(755,root,root) /etc/profile.d/ssh-agent.sh
%attr(755,root,root) /etc/X11/xinit/xinitrc.d/ssh-agent.sh
%endif
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/slogin.1*
%{_mandir}/man1/sftp.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
%{_mandir}/man5/ssh_config.5*
%lang(it) %{_mandir}/it/man1/ssh.1*
%lang(it) %{_mandir}/it/man5/ssh_config.5*
%lang(pl) %{_mandir}/pl/man1/scp.1*
%lang(zh_CN) %{_mandir}/zh_CN/man1/scp.1*

# for host-based auth (suid required for accessing private host key)
#%attr(4755,root,root) %{_libexecdir}/ssh-keysign
#%{_mandir}/man8/ssh-keysign.8*

%files server
%defattr(644,root,root,755)
%attr(755,root,root) %{_sbindir}/sshd
%attr(755,root,root) %{_libexecdir}/sftp-server
%attr(755,root,root) %{_libexecdir}/ssh-keysign
%{_mandir}/man8/sshd.8*
%{_mandir}/man8/sftp-server.8*
%{_mandir}/man8/ssh-keysign.8*
%{_mandir}/man5/sshd_config.5*
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/sshd_config
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/pam.d/sshd
%attr(640,root,root) %{_sysconfdir}/moduli
%attr(754,root,root) /etc/rc.d/init.d/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/sysconfig/sshd
%attr(640,root,root) %config(noreplace) %verify(not md5 size mtime) /etc/security/blacklist.sshd

%if %{with gnome} || %{with gtk}
%files gnome-askpass
%defattr(644,root,root,755)
%attr(644,root,root) %config(noreplace,missingok) %verify(not md5 size mtime) /etc/env.d/GNOME_SSH_ASKPASS*
%dir %{_libexecdir}/ssh
%attr(755,root,root) %{_libexecdir}/ssh/ssh-askpass
%attr(755,root,root) %{_libexecdir}/ssh-askpass
%endif
