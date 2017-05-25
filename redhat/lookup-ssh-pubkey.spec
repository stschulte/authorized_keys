Name:    lookup-ssh-pubkey
Version: 1.0.0
Release: 1%{?dist}
Summary: Lookup public keys from a fixed directory
License: MIT

Source0: %{name}-%{version}.tar.gz

%description
Tool to be used by sshd to lookup authorized keys for users
from a fixed location instead of ~user/.ssh/authorized_keys

%prep
%setup -q -c

%build
mkdir build
cd build
%cmake -DCMAKE_INSTALL_SYSCONFDIR:PATH=%{_sysconfdir} ..
make %{?_smp_mflags}

%install
cd build
make install DESTDIR=%{buildroot}

%files
%{_bindir}/lookup-ssh-pubkey
%dir %{_sysconfdir}/ssh-public-keys.d
%{_mandir}/man1/lookup-ssh-pubkey.1*

%changelog
* Thu May 25 2017 Stefan Schulte <stschulte@posteo.de> 1.0.0
- initial version
