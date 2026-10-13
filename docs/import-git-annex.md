# Importing git-annex repositories

If your files live in git-annex repositories spread over many disks, Varsto
can take them over disk by disk. Each repository becomes one Varsto folder.
Every disk that holds a clone of the repository adds what it has, until the
folder is complete; then the disks are no longer needed by Varsto.

Varsto reads the repositories with plain `git` commands and reads the
annexed files straight from `.git/annex/objects`. It never runs git-annex,
never takes a lock and never writes anything to a repository or a disk.

## The disk-by-disk workflow

1. Plug in the first disk and import its clone:

   ```sh
   varsto import git-annex /media/disk-03/photos
   ```

   The folder is created (named after the repository's directory, here
   `photos`; choose another name with `--folder`). By default it is attached
   *selectively*: the imported files are placeholders on this computer and
   their encrypted blocks go to your storages. To keep a full copy here as
   well, give `--dest ~/Photos`.

   Every annexed file whose content is on the disk is read once, checked
   against the hash in its git-annex key while it is encrypted and uploaded,
   and becomes a file of the folder. Files committed to git directly (small
   files) are imported too. A key used by several files is read once.

2. Read the report:

   ```text
   Imported into folder «photos» (new) from «disk-03 photos» (/media/disk-03/photos), commit 3f2c9a1b7d0e
     imported: 41 220 keys (812.4 GB) in 41 873 file(s)
     already imported: 0 keys
     damaged here: 1 (content does not match its hash; not imported from this copy):
       2014/05/IMG_0042.JPG [SHA256E-s2412311--9f86...]: sha256 is 3a1c..., expected 9f86...
     missing here: 3 004 keys in 3 010 file(s) (210.3 GB), awaiting import
     Insert next: «disk-07 photos» (has 2 890 of the missing keys, 205.0 GB)
             then: «disk-11 photos» (has 114 of the missing keys, 5.3 GB)
     (git-annex location logs may be out of date)
   ```

   Files whose content is not on this disk are *awaiting import*: Varsto
   lists them (`varsto folder files photos`, the file list in the app) with
   their size, but they are not synced as files yet, so no other device sees
   an empty file or a deletion. A file whose content does not match its key
   is reported as damaged on this disk and is not imported from it; another
   disk's copy will be used. The suggestions come from git-annex's location
   logs, which can be out of date.

3. Plug in the disk it suggests and run the same command for it:

   ```sh
   varsto import git-annex /media/disk-07/photos
   ```

   The clone is recognised as the same repository (by the history of its
   `git-annex` branch), so the same folder continues. Content that is
   already in Varsto is not read again.

4. Repeat until nothing is missing, then check:

   ```sh
   varsto import status photos
   varsto import status photos --missing     # what is still missing, and where
   varsto import verify photos
   ```

   `verify` says *complete* when every file of the repository's current
   commit is in the folder with the imported content, every block is on a
   storage and the folder's durability policy is met (for example a copy in
   the cloud, one at home, and checked by another of your devices within 30
   days). Then the annex disks are no longer needed by Varsto. Varsto never
   deletes anything on them; what you do with them is up to you.

You can continue on another computer: the import's bookkeeping travels with
the folder (encrypted like the rest), so any device of the vault can import
the next disk. On a computer where the folder is not attached yet, the import
attaches it (selectively, or with `--dest`).

An import can be interrupted at any time. Run the same command again and it
carries on: what was imported is not read again.

## Options

- `--ref BRANCH|TAG|COMMIT`: import that commit instead of `HEAD`.
- `--folder NAME`: the folder for a first import. A repository imported
  before always continues its own folder, and a name already used by
  another folder is refused.
- `--dest DIR`: keep a full copy of the folder in `DIR` on this device.
- `--selective`: placeholders only (the default without `--dest`).
- `--dry-run`: list and plan, change nothing.
- `--no-verify`: do not check content against the keys' hashes (faster on a
  slow CPU; damage on the disk then goes unnoticed).
- `--json`: the report as JSON.

## What is and is not imported

- Locked files (symlinks into `.git/annex/objects`) and unlocked files
  (pointer files) are imported from the annex object store; files committed
  to git directly are read from git.
- Keys with a hash (`SHA256E`, `SHA256`, `SHA512`, `SHA1`, `MD5`,
  `BLAKE2B*`, `BLAKE2S256` and their `E` variants) are verified. `WORM` and
  `URL` keys carry no hash and are imported as read (the report counts them).
- Symbolic links that are not annexed files, submodules, and names Varsto
  cannot use (with `:` or `\`, Windows reserved names) are reported and not
  imported.
- git-annex metadata (tags and fields) is not imported yet.
- Special remotes are not read: only what is on the disk at hand counts.
