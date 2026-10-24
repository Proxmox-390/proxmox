//! Reading the changelogs that installed packages ship with their documentation.

use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;

use proxmox_deb_version::cmp_versions;

use crate::{ChangelogEntry, parse_changelog};

/// Directory in which packages install their documentation, including their changelogs.
pub const DOC_DIR: &str = "/usr/share/doc";

/// Changelogs larger than this when decompressed are rejected, the biggest ones are a few MiB.
const MAX_CHANGELOG_SIZE: u64 = 16 * 1024 * 1024;

/// Errors from reading the changelog of an installed package.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The package name is not valid as per Debian policy.
    #[error("invalid package name '{0}'")]
    InvalidPackageName(String),

    /// The package is not installed, or has no Debian changelog, for example if the documentation
    /// was excluded from installing.
    #[error("no changelog found for package '{0}'")]
    NotFound(String),

    /// Reading a changelog file failed.
    #[error("failed to read {path:?} - {error}")]
    Read { path: PathBuf, error: io::Error },

    /// A changelog file is larger than expected.
    #[error("{path:?} is larger than {MAX_CHANGELOG_SIZE} bytes when decompressed")]
    TooLarge { path: PathBuf },
}

/// Reads the Debian changelog of an installed package, usually newest entries first.
///
/// Non-native packages install it as `changelog.Debian.gz`, native ones as `changelog.gz`. The
/// entries of binary-only uploads, which rebuild a package without source changes, are kept in a
/// file per architecture, like `changelog.Debian.amd64.gz`, and get merged in by version. The
/// documentation directory may also be a symlink to the one of another package built from the same
/// source.
pub fn read_installed_changelog(package: &str) -> Result<Vec<ChangelogEntry>, Error> {
    read_installed_changelog_from(Path::new(DOC_DIR), package)
}

fn read_installed_changelog_from(
    doc_dir: &Path,
    package: &str,
) -> Result<Vec<ChangelogEntry>, Error> {
    if !is_valid_package_name(package) {
        return Err(Error::InvalidPackageName(package.to_string()));
    }
    let dir = doc_dir.join(package);

    let (text, binary_only_prefix) =
        match read_first(&dir, &["changelog.Debian.gz", "changelog.Debian"])? {
            Some(text) => (text, "changelog.Debian."),
            // a non-native package's changelog.gz is the upstream one, which is no Debian changelog
            None => (
                read_first(&dir, &["changelog.gz", "changelog"])?.unwrap_or_default(),
                "changelog.",
            ),
        };
    let mut entries = parse_changelog(&text);
    let Some(source) = entries.first().map(|entry| entry.package.clone()) else {
        return Err(Error::NotFound(package.to_string()));
    };

    for path in binary_only_changelogs(&dir, binary_only_prefix)? {
        if let Some(text) = read_file(&path)? {
            // other files can have such a name too, for example upstream ones of native packages
            for entry in parse_changelog(&text) {
                if entry.package == source {
                    insert_by_version(&mut entries, entry);
                }
            }
        }
    }

    Ok(entries)
}

/// Checks a package name as per Debian policy, which also keeps it from leaving the documentation
/// directory.
fn is_valid_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
}

/// Reads the first of the given files that exists in `dir`.
fn read_first(dir: &Path, names: &[&str]) -> Result<Option<String>, Error> {
    for name in names {
        if let Some(text) = read_file(&dir.join(name))? {
            return Ok(Some(text));
        }
    }
    Ok(None)
}

/// Reads a changelog file, decompressing it if its name ends with `.gz`, which can also consist of
/// several gzip members.
fn read_file(path: &Path) -> Result<Option<String>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Read {
                path: path.to_owned(),
                error,
            });
        }
    };
    let reader: Box<dyn Read> = if path.extension().is_some_and(|ext| ext == "gz") {
        Box::new(MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let mut data = Vec::new();
    reader
        .take(MAX_CHANGELOG_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|error| Error::Read {
            path: path.to_owned(),
            error,
        })?;
    if data.len() as u64 > MAX_CHANGELOG_SIZE {
        return Err(Error::TooLarge {
            path: path.to_owned(),
        });
    }
    // very old entries can be in other encodings than UTF-8
    Ok(Some(String::from_utf8_lossy(&data).into_owned()))
}

/// Lists the changelogs of binary-only uploads in `dir`, named like `<prefix><arch>.gz`.
fn binary_only_changelogs(dir: &Path, prefix: &str) -> Result<Vec<PathBuf>, Error> {
    let read_error = |error| Error::Read {
        path: dir.to_owned(),
        error,
    };
    let mut paths = Vec::new();
    for dir_entry in std::fs::read_dir(dir).map_err(read_error)? {
        let name = dir_entry.map_err(read_error)?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let arch = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(".gz"));
        if arch.is_some_and(|arch| {
            !arch.is_empty()
                && arch
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }) {
            paths.push(dir.join(name));
        }
    }
    paths.sort();
    Ok(paths)
}

/// Inserts an entry before the first one with an older version, keeping the order otherwise.
fn insert_by_version(entries: &mut Vec<ChangelogEntry>, entry: ChangelogEntry) {
    let position = entries
        .iter()
        .position(|other| {
            cmp_versions(&other.version, &entry.version).is_ok_and(|ord| ord == Ordering::Less)
        })
        .unwrap_or(entries.len());
    entries.insert(position, entry);
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};

    use super::*;

    /// A documentation directory in the temporary directory, removed when dropped.
    struct DocDir(PathBuf);

    impl DocDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "proxmox-deb-changelog-test-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("creating test directory");
            Self(path)
        }

        fn write(&self, file: &str, content: &[u8]) {
            let path = self.0.join(file);
            std::fs::create_dir_all(path.parent().expect("file in a directory"))
                .expect("creating package directory");
            if file.ends_with(".gz") {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
                encoder.write_all(content).expect("compressing");
                std::fs::write(path, encoder.finish().expect("compressing"))
            } else {
                std::fs::write(path, content)
            }
            .expect("writing test file");
        }

        fn read(&self, package: &str) -> Result<Vec<String>, Error> {
            Ok(read_installed_changelog_from(&self.0, package)?
                .into_iter()
                .map(|entry| entry.version)
                .collect())
        }
    }

    impl Drop for DocDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry(package: &str, version: &str, binary_only: bool) -> String {
        let extra = if binary_only { ", binary-only=yes" } else { "" };
        format!(
            "{package} ({version}) trixie; urgency=medium{extra}\n\n  * change\n\n \
             -- Some One <some.one@example.com>  Fri, 16 Oct 2026 09:00:00 +0200\n\n"
        )
    }

    #[test]
    fn read_installed() {
        let docs = DocDir::new("read");
        let debian = [entry("foo", "2.0-1", false), entry("foo", "1.0-1", false)].concat();
        docs.write("libfoo/changelog.Debian.gz", debian.as_bytes());
        docs.write(
            "libfoo/changelog.gz",
            b"upstream changes, no Debian changelog\n",
        );
        docs.write(
            "libfoo/changelog.Debian.amd64.gz",
            [
                entry("foo", "2.0-1+b2", true),
                entry("foo", "1.0-1+b1", true),
            ]
            .concat()
            .as_bytes(),
        );
        assert_eq!(
            docs.read("libfoo").expect("valid changelog"),
            ["2.0-1+b2", "2.0-1", "1.0-1+b1", "1.0-1"]
        );

        // gzip files can consist of several members
        let gzip = |text: &str| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(text.as_bytes()).expect("compressing");
            encoder.finish().expect("compressing")
        };
        std::fs::create_dir_all(docs.0.join("members")).expect("creating package directory");
        std::fs::write(
            docs.0.join("members/changelog.Debian.gz"),
            [
                gzip(&entry("members", "2", false)),
                gzip(&entry("members", "1", false)),
            ]
            .concat(),
        )
        .expect("writing test file");
        assert_eq!(docs.read("members").expect("valid changelog"), ["2", "1"]);

        // native packages have no changelog.Debian.gz, and their binary-only uploads are named
        // after their changelog
        docs.write(
            "native/changelog.gz",
            [entry("native", "3.1", false), entry("native", "3.0", false)]
                .concat()
                .as_bytes(),
        );
        docs.write(
            "native/changelog.amd64.gz",
            entry("native", "3.1+b1", true).as_bytes(),
        );
        // but files of other sources or other names are no binary-only changelogs
        docs.write(
            "native/changelog.old.gz",
            entry("other", "4.0", false).as_bytes(),
        );
        docs.write(
            "native/changelog.Debian.amd64.gz",
            entry("native", "3.0+b1", true).as_bytes(),
        );
        assert_eq!(
            docs.read("native").expect("valid changelog"),
            ["3.1+b1", "3.1", "3.0"]
        );

        std::os::unix::fs::symlink("libfoo", docs.0.join("foo-utils")).expect("symlink");
        assert_eq!(docs.read("foo-utils").expect("valid changelog").len(), 4);
    }

    #[test]
    fn read_installed_errors() {
        let docs = DocDir::new("errors");
        docs.write("upstream/changelog.gz", b"upstream changes only\n");
        assert!(matches!(docs.read("upstream"), Err(Error::NotFound(_))));
        assert!(matches!(docs.read("missing"), Err(Error::NotFound(_))));

        for name in ["", "a", "../etc", "foo/bar", "Foo", "-foo", "foo bar"] {
            assert!(
                matches!(docs.read(name), Err(Error::InvalidPackageName(_))),
                "{name:?}"
            );
        }

        let big = vec![b' '; MAX_CHANGELOG_SIZE as usize + 1];
        docs.write("big/changelog.Debian.gz", &big);
        assert!(matches!(docs.read("big"), Err(Error::TooLarge { .. })));
    }
}
