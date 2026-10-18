// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The commands of folder membership in storage format 3 (design section 6,
//! work package 8b): `folder request | requests | approve | deny | members |
//! role | remove <folder> <device> | resolve-epoch`, `recovery escrow`,
//! `recovery kit --recovery-words`, the recovery warning of `varsto status`
//! and the stub of `join --recovery-words`.
//!
//! The operations are the engine's (`Engine::f3_*`, behind the `format3`
//! feature of varsto-core). A build without the feature has the same
//! commands, and each answers that it is not available in this build.

use super::{Cli, FolderCmd};
use anyhow::{bail, Result};
use std::path::Path;

#[cfg(not(feature = "format3"))]
mod imp {
    use super::*;

    pub const UNAVAILABLE: &str = "folder membership of storage format 3 is not available in this build of Varsto (it is built without the format3 feature)";

    pub fn folder(_cli: &Cli, _home: &Path, cmd: &FolderCmd) -> Result<bool> {
        match cmd {
            FolderCmd::Request { .. }
            | FolderCmd::Requests { .. }
            | FolderCmd::Approve { .. }
            | FolderCmd::Deny { .. }
            | FolderCmd::Members { .. }
            | FolderCmd::Role { .. }
            | FolderCmd::ResolveEpoch { .. }
            | FolderCmd::CreateF3 { .. }
            | FolderCmd::Remove {
                device: Some(_), ..
            } => bail!("{UNAVAILABLE}"),
            _ => Ok(false),
        }
    }

    pub fn recovery_escrow(
        _cli: &Cli,
        _home: &Path,
        _folder: Option<&str>,
        _with_recovery_key: bool,
        _file: Option<&Path>,
    ) -> Result<()> {
        bail!("{UNAVAILABLE}")
    }

    pub fn recovery_kit(_home: &Path, _new: bool) -> Result<()> {
        bail!("{UNAVAILABLE}")
    }

    pub fn join_recovery_words(_engine: &mut varsto_core::engine::Engine) -> Result<Vec<String>> {
        bail!("{UNAVAILABLE}")
    }

    pub fn status_warnings(_engine: &mut varsto_core::engine::Engine) {}

    pub fn folder_add_recovery_key(
        _file: Option<&Path>,
        _prompt: bool,
    ) -> Result<Option<varsto_core::membership3::RecoveryKey>> {
        Ok(None)
    }

    pub fn recovery_words_given(
        _file: Option<&Path>,
    ) -> Result<Option<zeroize::Zeroizing<String>>> {
        Ok(None)
    }

    pub fn recovery_words_text(_file: Option<&Path>) -> Result<zeroize::Zeroizing<String>> {
        bail!("{UNAVAILABLE}")
    }
}

#[cfg(feature = "format3")]
mod imp {
    use super::*;
    use varsto_core::engine::{
        parse_folder_role, Engine, FolderMembers, FolderRemoval, FolderRequest,
    };
    use varsto_core::membership3::RecoveryKey;

    /// A question on standard error, answered on standard input (also when
    /// it is a pipe: `echo y |`). No answer is no.
    fn ask(question: &str) -> Result<bool> {
        use std::io::{BufRead, Write};
        eprint!("{question} [y/N] ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
    }

    fn short(id: &str) -> &str {
        &id[..id.len().min(8)]
    }

    fn request_line(r: &FolderRequest) -> String {
        format!(
            "{} wants {} in folder {} (device {}): {}",
            r.device,
            r.role_wanted,
            r.folder,
            short(&r.device_id),
            r.fingerprint
        )
    }

    pub fn members_text(m: &FolderMembers) -> String {
        let mut out = format!(
            "folder {} ({}), folder epoch {}, this device: {}\n",
            m.folder,
            short(&m.folder_id),
            m.epoch,
            m.your_role.as_deref().unwrap_or("not a participant")
        );
        for p in &m.participants {
            out += &format!(
                "  {:<7} {} ({}){}\n",
                p.role,
                p.device,
                short(&p.device_id),
                if p.this_device { " (this device)" } else { "" }
            );
        }
        for d in &m.denied {
            out += &format!("  denied  {} ({})\n", d.device, short(&d.device_id));
        }
        for r in &m.pending {
            out += &format!("  pending {}\n", request_line(r));
        }
        for e in &m.unresolved_epochs {
            out += &format!("  folder epoch {e} was started by two owners: varsto folder resolve-epoch {} {e} --keep <device>\n", m.folder);
        }
        out.trim_end().to_string()
    }

    fn recovery_words_input(with_recovery_key: bool, file: Option<&Path>) -> Result<RecoveryKey> {
        let text = if with_recovery_key {
            match std::env::var("VARSTO_RECOVERY_WORDS")
                .ok()
                .filter(|v| !v.trim().is_empty())
            {
                Some(v) => {
                    varsto_core::logging::register_secret(v.trim());
                    zeroize::Zeroizing::new(v.trim().to_string())
                }
                None => {
                    bail!("--with-recovery-key needs the recovery words in VARSTO_RECOVERY_WORDS")
                }
            }
        } else {
            crate::secret_input(file, "VARSTO_RECOVERY_WORDS", "Recovery words (24): ", true)?
        };
        RecoveryKey::from_words(&text)
    }

    pub fn folder(cli: &Cli, home: &Path, cmd: &FolderCmd) -> Result<bool> {
        match cmd {
            FolderCmd::Request { folder, role } => {
                parse_folder_role(role)?;
                let mut e = crate::open_engine(home)?;
                let r = e.f3_folder_request(folder, role)?;
                crate::print(cli, &r, |r| {
                    format!(
                        "Asked the owners of folder {} for the {} role.\nThis device is {}; its six words are:\n  {}\nGive an owner these words (not through the same channel as the request); they compare them before approving.",
                        r.folder, r.role_wanted, r.device, r.fingerprint
                    )
                })?;
            }
            FolderCmd::Requests { folder } => {
                let mut e = crate::open_engine(home)?;
                let rs = e.f3_requests(folder.as_deref())?;
                crate::print(cli, &rs, |rs| {
                    if rs.is_empty() {
                        "no requests are waiting".to_string()
                    } else {
                        rs.iter().map(request_line).collect::<Vec<_>>().join("\n")
                    }
                })?;
            }
            FolderCmd::Approve {
                folder,
                device,
                role,
                yes,
            } => {
                let mut e = crate::open_engine(home)?;
                let pending = e.f3_requests(Some(folder))?;
                let lower = device.to_ascii_lowercase();
                let hits: Vec<&FolderRequest> = pending
                    .iter()
                    .filter(|r| {
                        r.device == *device || (lower.len() >= 4 && r.device_id.starts_with(&lower))
                    })
                    .collect();
                let req = match hits.as_slice() {
                    [one] => (*one).clone(),
                    [] => bail!(
                        "no pending request of {device} for folder {folder} (see `varsto folder requests {folder}`)"
                    ),
                    _ => bail!("several pending requests fit {device}: give the device id"),
                };
                let role = role.clone().unwrap_or_else(|| req.role_wanted.clone());
                eprintln!(
                    "Device {} ({}) asks for the {} role in folder {}.\nIts six words: {}\nOn that device `varsto folder request` printed the same six words.",
                    req.device,
                    short(&req.device_id),
                    role,
                    req.folder,
                    req.fingerprint
                );
                if !*yes && !ask("Do the six words match?")? {
                    bail!("not approved: nothing was granted");
                }
                let m =
                    e.f3_approve(folder, &req.device_id, Some(&role), Some(&req.fingerprint))?;
                crate::print(cli, &m, |m| {
                    format!("approved {} as {role}\n{}", req.device, members_text(m))
                })?;
            }
            FolderCmd::Deny { folder, device } => {
                let mut e = crate::open_engine(home)?;
                let m = e.f3_deny(folder, device)?;
                crate::print(cli, &m, |m| format!("denied {device}\n{}", members_text(m)))?;
            }
            FolderCmd::Members { folder } => {
                let mut e = crate::open_engine(home)?;
                let m = e.f3_members(folder)?;
                crate::print(cli, &m, members_text)?;
            }
            FolderCmd::Role {
                folder,
                device,
                role,
            } => {
                let mut e = crate::open_engine(home)?;
                let m = e.f3_set_role(folder, device, role)?;
                crate::print(cli, &m, |m| {
                    format!("{device} is now {role}\n{}", members_text(m))
                })?;
            }
            FolderCmd::Remove {
                name,
                device: Some(device),
                yes,
                ..
            } => {
                let mut e = crate::open_engine(home)?;
                if !*yes {
                    let ok = ask(&format!(
                        "Remove {device} from folder {name}? This starts a new folder epoch that {device} never gets; what it already read stays readable to it."
                    ))?;
                    if !ok {
                        bail!("not removed (answer y, or pass --yes)");
                    }
                }
                let r: FolderRemoval = e.f3_remove(name, device, None)?;
                crate::print(cli, &r, |r| {
                    let mut t = format!(
                        "removed {} from folder {}: folder epoch {} started, keys sent to {}",
                        r.removed,
                        r.folder,
                        r.epoch,
                        if r.granted_to.is_empty() {
                            "no other device".to_string()
                        } else {
                            r.granted_to.join(", ")
                        }
                    );
                    if !r.escrowed {
                        t += &format!(
                            "\nThe new epoch has no recovery copy yet: run varsto recovery escrow {}",
                            r.folder
                        );
                    }
                    t
                })?;
            }
            FolderCmd::ResolveEpoch {
                folder,
                epoch,
                keep,
            } => {
                let mut e = crate::open_engine(home)?;
                let m = e.f3_resolve_epoch(folder, *epoch, keep)?;
                crate::print(cli, &m, |m| {
                    format!("kept {keep}'s folder epoch {epoch}\n{}", members_text(m))
                })?;
            }
            FolderCmd::CreateF3 { name } => {
                let mut e = crate::open_engine(home)?;
                let id = e.f3_folder_create(name, None)?;
                crate::print(
                    cli,
                    &serde_json::json!({"folder_id": id, "name": name}),
                    |_| {
                        format!(
                            "folder {name} ({}) created in the membership records",
                            short(&id)
                        )
                    },
                )?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn recovery_escrow(
        cli: &Cli,
        home: &Path,
        folder: Option<&str>,
        with_recovery_key: bool,
        file: Option<&Path>,
    ) -> Result<()> {
        let mut e = crate::open_engine(home)?;
        let missing = e.f3_missing_escrows()?;
        let missing: Vec<_> = missing
            .into_iter()
            .filter(|m| folder.is_none_or(|f| m.folder == f || m.folder_id.starts_with(f)))
            .collect();
        if missing.is_empty() {
            return crate::print(cli, &Vec::<String>::new(), |_| {
                "every folder this device holds has a recovery copy".to_string()
            });
        }
        let k1 = recovery_words_input(with_recovery_key, file)?;
        let written = e.f3_write_escrows(folder, &k1)?;
        crate::print(cli, &written, |w| {
            let mut t = format!("wrote {} recovery copies:", w.len());
            for x in w {
                t += &format!("\n  folder {} epoch {}", x.folder, x.epoch);
            }
            t
        })
    }

    pub fn recovery_kit(home: &Path, new: bool) -> Result<()> {
        let e = crate::open_engine(home)?;
        let (k1, fresh) = if new {
            (RecoveryKey::generate(), true)
        } else {
            (recovery_words_input(false, None)?, false)
        };
        print!("{}", e.f3_kit_text(&k1)?);
        if fresh {
            println!("\nThis recovery key is new and was not stored anywhere. Folders get recovery copies under it with `varsto recovery escrow` (it asks for these words).");
        }
        Ok(())
    }

    /// `join --recovery-words`: after joining with the vault words, the
    /// recovery words (asked hidden, or from VARSTO_RECOVERY_WORDS or a
    /// pipe) open the recovery copy of every folder. Returns their names.
    pub fn join_recovery_words(engine: &mut Engine) -> Result<Vec<String>> {
        let k1 = recovery_words_input(false, None)?;
        engine.recover_folders(&k1)
    }

    /// The recovery words as text (checked): a file, VARSTO_RECOVERY_WORDS,
    /// a pipe or a hidden prompt.
    pub fn recovery_words_text(file: Option<&Path>) -> Result<zeroize::Zeroizing<String>> {
        let text =
            crate::secret_input(file, "VARSTO_RECOVERY_WORDS", "Recovery words (24): ", true)?;
        RecoveryKey::from_words(&text)?;
        Ok(text)
    }

    /// The recovery words given for this command without asking: a file
    /// or VARSTO_RECOVERY_WORDS.
    pub fn recovery_words_given(file: Option<&Path>) -> Result<Option<zeroize::Zeroizing<String>>> {
        if file.is_none()
            && std::env::var("VARSTO_RECOVERY_WORDS")
                .ok()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Ok(None);
        }
        let text = crate::secret_input(file, "VARSTO_RECOVERY_WORDS", "", false)?;
        // Checked here, so a mistyped word does not create a folder first.
        RecoveryKey::from_words(&text)?;
        Ok(Some(text))
    }

    /// The recovery key for `folder add`: given (`recovery_words_given`),
    /// else asked on a terminal (with `prompt`), where an empty answer
    /// leaves the recovery copy for later. Without a terminal and without
    /// words the folder is made without it, and `varsto status` warns.
    pub fn folder_add_recovery_key(
        file: Option<&Path>,
        prompt: bool,
    ) -> Result<Option<RecoveryKey>> {
        use std::io::IsTerminal;
        if let Some(text) = recovery_words_given(file)? {
            return RecoveryKey::from_words(&text).map(Some);
        }
        if !prompt || !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        let text = zeroize::Zeroizing::new(rpassword::prompt_password(
            "Recovery words (24) for the folder's recovery copy (Enter: write it later with `varsto recovery escrow`): ",
        )?);
        if text.trim().is_empty() {
            return Ok(None);
        }
        varsto_core::logging::register_secret(text.trim());
        RecoveryKey::from_words(text.trim()).map(Some)
    }

    /// The recovery warnings of `varsto status`, on standard error.
    pub fn status_warnings(engine: &mut Engine) {
        match engine.f3_missing_escrows() {
            Ok(list) => {
                for m in list {
                    eprintln!("warning: {}", m.warning);
                }
            }
            Err(e) => log::debug!("recovery copies not checked: {e:#}"),
        }
    }
}

pub use imp::{
    folder, folder_add_recovery_key, join_recovery_words, recovery_escrow, recovery_kit,
    recovery_words_given, recovery_words_text, status_warnings,
};
