# Importing a local folder

```sh
varsto import dir "/media/old-drive/Pictures"
varsto import dir "/media/old-drive/Pictures" --remove-source
```

The folder (a directory of this computer, an external drive, a network
share) becomes one Varsto folder. Its files are read in path order, one
after the other (the fastest way on a spinning disk), encrypted and
uploaded to your storages. Symbolic links are never followed (they are
listed in the report), and sockets, devices and pipes are skipped. Running
the import again brings changed files over as new versions; files deleted
at the source stay in Varsto.

In the app: **Import** in the side bar (under **More** on a phone).

Varsto refuses to import its own folders or its own data directory.

## Removing the source files once they are safe

With `--remove-source` (the checkbox *Remove source files once they are
safely stored and the policy is met* in the app), Varsto removes each source
file only when all of this holds at the moment of removal:

1. The file is unchanged since it was imported: same size, same
   modification time, and the same content (it is read and hashed again).
2. Varsto's folder still has that file with that content (it was not
   changed or deleted in Varsto since).
3. Every block of it is on one of your storages (not only on devices or a
   transferrer disk), and one copy of each block was read back intact.
4. The folder's durability policy is met for those blocks right now. A
   folder without a policy of its own has the default one: a copy in
   external storage, one on your own devices or disks, and every block
   checked by another of your devices within 30 days.

Files that do not qualify yet stay, with the reason:

```text
3 file(s) stay for now:
  2019/IMG_1001.JPG: waiting for the policy (...): 1 chunks were not verified by another device within 30 days
  notes.txt: changed since it was imported
```

Run the import again later, or just the cleanup:

```sh
varsto import cleanup Pictures            # asks before removing
varsto import cleanup Pictures --dry-run  # only shows what would go
```

Directories left empty are removed too, never the source directory itself,
and nothing outside it is ever touched. Varsto lists the count and size and
asks before removing anything unless you pass `--yes`. Every removed file is
logged (`varsto import status` shows the total). A git-annex repository is
never emptied this way: use `varsto import git-annex` for it.
