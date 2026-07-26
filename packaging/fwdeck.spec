# RPM spec for building fwdeck on Fedora COPR (dnf copr enable madebydaniz/fwdeck).
#
# COPR builds are offline by default; enable network for this project (or vendor
# deps with `cargo vendor` and drop a .cargo/config.toml) so `cargo build` can
# fetch crates. Bump Version and %changelog per release.
Name:           fwdeck
# x-release-please-start-version
Version:        0.2.0
# x-release-please-end
Release:        1%{?dist}
Summary:        A safety-first terminal UI for firewalld

License:        MIT
URL:            https://github.com/madebydaniz/fwdeck
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
Requires:       firewalld

%description
FWDeck is a safety-first terminal UI for firewalld — manage zones, services,
ports, and rich rules from the keyboard, with runtime vs permanent scope on
every row and a dead-man's switch that auto-reverts a change that cuts your
session unless you confirm connectivity still works.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked

%install
install -Dm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -Dm0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
target/release/%{name} completions bash > %{name}.bash
install -Dm0644 %{name}.bash %{buildroot}%{_datadir}/bash-completion/completions/%{name}
target/release/%{name} completions fish > %{name}.fish
install -Dm0644 %{name}.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/%{name}.fish
target/release/%{name} manpage > %{name}.1
install -Dm0644 %{name}.1 %{buildroot}%{_mandir}/man1/%{name}.1

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%{_mandir}/man1/%{name}.1*

%changelog
* Sat Jul 26 2026 Daniel Niazmand <daniel@xcoorp.com> - 0.2.0-1
- Production hardening: safety fixes, supply-chain, and CI/security tooling.
* Sat Jul 26 2026 Daniel Niazmand <daniel@xcoorp.com> - 0.1.2-1
- Initial COPR package.
