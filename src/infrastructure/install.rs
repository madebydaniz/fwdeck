//! Best-effort detection of how this fwdeck binary was installed, so `doctor`
//! can print the *correct* upgrade command for the user's setup. Pure inference
//! from the running executable's path — no network, no subprocess, and it never
//! guesses a package-manager command it can't be sure of: an ambiguous install
//! points at the releases page rather than a command that might shadow a
//! package-managed binary.

use std::path::Path;

/// Canonical place new versions are published.
const RELEASES_URL: &str = "https://github.com/madebydaniz/fwdeck/releases";

/// How this binary appears to have been installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    /// `cargo install` (a cargo bin directory).
    Cargo,
    /// The immutable Nix store.
    Nix,
    /// The `install.sh` script or a manual copy into `~/.local/bin` or
    /// `/usr/local/bin`.
    Script,
    /// A distro package in a system bin dir — deb/rpm/AUR/Copr are
    /// indistinguishable from the path alone.
    SystemPackage,
    /// The path gave no usable signal.
    Unknown,
}

impl InstallMethod {
    /// Detects the install method from the running executable's canonicalized
    /// path (symlinks resolved). Returns [`InstallMethod::Unknown`] if the path
    /// can't be read.
    #[must_use]
    pub fn detect() -> Self {
        let Ok(exe) = std::env::current_exe() else {
            return Self::Unknown;
        };
        // Resolve symlinks so e.g. a /usr/bin shim into the Nix store, or a
        // ~/.local/bin symlink, classifies by its real location.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        Self::from_path(&exe)
    }

    fn from_path(exe: &Path) -> Self {
        let path = exe.to_string_lossy();
        if path.contains("/nix/store/") {
            Self::Nix
        } else if path.contains("/.cargo/bin/") || path.contains("/cargo/bin/") {
            Self::Cargo
        } else if path.contains("/.local/bin/") || path.starts_with("/usr/local/bin/") {
            Self::Script
        } else if path.starts_with("/usr/bin/") || path.starts_with("/bin/") {
            Self::SystemPackage
        } else {
            Self::Unknown
        }
    }

    /// Short label for display (`"cargo install"`, `"Nix"`, …).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo install",
            Self::Nix => "Nix",
            Self::Script => "install script / manual",
            Self::SystemPackage => "system package",
            Self::Unknown => "unknown",
        }
    }

    /// A copy-pasteable line telling the operator how to upgrade — or, when the
    /// method is ambiguous, where to get the new version. Never a confidently
    /// wrong command for a package-managed binary.
    #[must_use]
    pub fn upgrade_hint(self) -> String {
        match self {
            Self::Cargo => "cargo install fwdeck --locked".to_owned(),
            Self::Nix => "nix profile upgrade fwdeck (or bump your flake input)".to_owned(),
            Self::Script => {
                format!(
                    "re-run the install script (it re-verifies the signature) — see {RELEASES_URL}"
                )
            }
            Self::SystemPackage => {
                format!(
                    "upgrade via your package manager (dnf/apt/pacman/AUR/Copr) — see {RELEASES_URL}"
                )
            }
            Self::Unknown => format!("see {RELEASES_URL}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_path() {
        let cases = [
            ("/home/x/.cargo/bin/fwdeck", InstallMethod::Cargo),
            (
                "/nix/store/abc123-fwdeck-0.3.0/bin/fwdeck",
                InstallMethod::Nix,
            ),
            ("/usr/local/bin/fwdeck", InstallMethod::Script),
            ("/home/x/.local/bin/fwdeck", InstallMethod::Script),
            ("/usr/bin/fwdeck", InstallMethod::SystemPackage),
            ("/opt/somewhere/fwdeck", InstallMethod::Unknown),
        ];
        for (path, want) in cases {
            assert_eq!(InstallMethod::from_path(Path::new(path)), want, "{path}");
        }
    }

    #[test]
    fn every_method_has_a_nonempty_hint() {
        for method in [
            InstallMethod::Cargo,
            InstallMethod::Nix,
            InstallMethod::Script,
            InstallMethod::SystemPackage,
            InstallMethod::Unknown,
        ] {
            assert!(!method.upgrade_hint().is_empty());
            assert!(!method.label().is_empty());
        }
    }
}
