#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Generates website/src/pages/compare*.html (run from the repo root).
import html, pathlib
OUT = pathlib.Path("website/src/pages")
CHECKED = "October 2026"

VARSTO = {
 "Where your files live": "On your own devices and on storages you choose: S3-compatible buckets, any rclone remote, local or network directories, and pools of removable disks.",
 "Account or central server": "None. There is no Varsto server; devices find each other through your storages and on the LAN.",
 "Encryption": "End-to-end, client-side, before anything leaves the device; hybrid post-quantum (ML-KEM for sharing keys, Ed25519 + ML-DSA-65 signatures). Not independently audited yet.",
 "Devices online together": "Not needed: devices sync through your storages, and directly peer to peer when they can reach each other.",
 "Knows where every copy is": "Yes: a signed ledger records which storage and device holds every block; durability policies (by default 1 copy anywhere, 1 external, 1 on your own devices or disks, checked by another device within 30 days) warn when a rule is not met.",
 "Removable and offline disks": "Yes: disk pools are filled, checked and recognised when they come back; files on a disk that is away ask for that disk.",
 "Licence and price": "Source-available (PolyForm Shield 1.0.0), free; you pay only your storage provider.",
 "Maturity": "Alpha: not for production data, formats may still change.",
}

P = [
 dict(slug="syncthing", name="Syncthing", url="https://syncthing.net/",
  what="Syncthing keeps folders identical across your own devices, continuously and without any cloud. It is free, mature and popular with technical users and home-lab setups: install it on a laptop, a desktop and a NAS, and the folders stay in step.",
  how="Devices connect peer to peer over TLS, identified by certificate-based device IDs; there is no account. Public discovery and relay servers run by the project help devices find each other, and you can host your own. Data lives only on the participating devices: there is no S3 or rclone backend and no provider copy. Versioning (trash can, simple, staggered or external) applies to changes received from other devices. Selective sync is done with ignore patterns; there are no placeholders. On Android the official app was discontinued in 2024 and a community fork continues; on iOS there is only a third-party client.",
  rows={
   "Where your files live": "Only on the devices that run Syncthing (a NAS or a server counts if it runs Syncthing).",
   "Account or central server": "None; project-run discovery and relay servers (self-hostable).",
   "Encryption": "TLS in transit; no encryption at rest of its own. \"Untrusted (encrypted) devices\" exist but are still marked beta.",
   "Devices online together": "Yes: two devices must be online at the same time to exchange changes, unless an always-on device is kept.",
   "Knows where every copy is": "No tracking of copies or copy counts.",
   "Removable and offline disks": "No removable-disk workflow.",
   "Licence and price": "Open source (MPL-2.0), free.",
   "Maturity": "Mature, long-running project (2.x).",
  },
  choose="Choose Syncthing when every copy should stay on machines you run, at least one of them is always on, and you want a mature, open-source tool with no accounts at all.",
  varsto="Choose Varsto when you want an encrypted copy in a bucket or on removable disks as well, devices that are rarely online together, a record of where every copy is, or a phone that reads files without keeping them in clear text.",
  sources=[("Syncthing", "https://syncthing.net/"), ("Untrusted devices", "https://docs.syncthing.net/users/untrusted.html"), ("File versioning", "https://docs.syncthing.net/users/versioning.html")]),
 dict(slug="resilio-sync", name="Resilio Sync", url="https://www.resilio.com/sync/",
  what="Resilio Sync syncs and shares folders between devices peer to peer, built on BitTorrent technology. The free Sync Home edition is for individuals; the company's main business is enterprise file transfer. Resilio was acquired by Nasuni in March 2026.",
  how="Devices connect directly; there is no account, and folders are shared with keys or links (read-only or read-write). Resilio-run trackers and relays help peers find each other. Data lives on the peers only; Sync Home has no S3 or rclone backend. Selective sync with placeholder files is available, and an \"encrypted folder\" lets a peer on an untrusted machine store data it cannot read (that peer is read-only and has no selective sync).",
  rows={
   "Where your files live": "Only on the peers (a NAS or server counts if it runs Resilio).",
   "Account or central server": "No account; Resilio-run trackers and relays.",
   "Encryption": "Encrypted in transit; encrypted folders for untrusted peers. Closed source, so not independently verifiable.",
   "Devices online together": "Yes, unless an always-on peer is kept.",
   "Knows where every copy is": "No tracking of copies or copy counts.",
   "Removable and offline disks": "No removable-disk workflow.",
   "Licence and price": "Proprietary; Sync Home is free.",
   "Maturity": "Mature commercial product; its future after the 2026 acquisition is not yet stated.",
  },
  choose="Choose Resilio Sync when you want fast BitTorrent-style transfer between always-on machines and easy sharing by key or link, and a closed-source vendor product is acceptable.",
  varsto="Varsto's peer-to-peer transfer is modelled on the same idea (encrypted blocks from several peers at once), but it adds your own storages as the always-available copy, a record of where every copy is, durability policies and an open specification of the formats.",
  sources=[("Resilio Sync", "https://www.resilio.com/sync/"), ("Encrypted folders", "https://www.resilio.com/blog/understanding-the-sync-encrypted-folder"), ("Nasuni acquires Resilio", "https://www.resilio.com/news/nasuni-acquires-resilio/")]),
 dict(slug="mega", name="MEGA", url="https://mega.io/",
  what="MEGA is end-to-end encrypted cloud storage for consumers and businesses, with generous storage plans, desktop sync, mobile apps and related services such as chat and a VPN.",
  how="You create an account and your files are stored in MEGA's data centres; devices sync through MEGA's servers. Files are encrypted on the client with per-file keys under a key derived from your password. In 2022 researchers at ETH Zurich published attacks on MEGA's cryptography; MEGA patched them, and the authors noted that a complete fix would need a redesign. There are desktop apps for Windows, macOS and Linux, mobile apps and a command-line client.",
  rows={
   "Where your files live": "In MEGA's cloud; you cannot use your own storage for the drive.",
   "Account or central server": "Account required; everything goes through MEGA.",
   "Encryption": "End-to-end, client-side; earlier weaknesses found by academic researchers were patched.",
   "Devices online together": "Not needed: the cloud holds the copy.",
   "Knows where every copy is": "One provider copy; no tracking across your own media.",
   "Removable and offline disks": "No removable-disk workflow.",
   "Licence and price": "Free tier and paid plans with transfer quotas; client source published (SDK BSD-licensed, desktop app under MEGA's own licence).",
   "Maturity": "Large, long-running service.",
  },
  choose="Choose MEGA when you want a lot of encrypted cloud space from one provider, with polished apps everywhere, and you are comfortable with the provider holding the only off-site copy.",
  varsto="Choose Varsto when you want to pick the storage yourself (or several providers at once), avoid lock-in, keep copies on your own disks as well, and know at every moment where each copy is.",
  sources=[("MEGA", "https://mega.io/"), ("MEGA desktop app source", "https://github.com/meganz/MEGAsync"), ("MEGA: Malleable Encryption Goes Awry (ETH Zurich)", "https://eprint.iacr.org/2022/959")]),
 dict(slug="filen", name="Filen", url="https://filen.io/",
  what="Filen is zero-knowledge encrypted cloud storage from Germany, for privacy-minded individuals and teams. It offers a drive, desktop sync, a network drive with on-demand files, notes and chat, at low prices.",
  how="You create an account and files are stored on Filen's servers in Germany, encrypted on the client (AES-256 per chunk) before upload. The clients and SDKs are open source under AGPL-3.0. The command-line client can expose your Filen storage locally over WebDAV or S3, but the data still lives at Filen. Free accounts can be deleted after a period of inactivity.",
  rows={
   "Where your files live": "In Filen's cloud in Germany; no own backends.",
   "Account or central server": "Account required.",
   "Encryption": "End-to-end, client-side (AES-256); open-source clients.",
   "Devices online together": "Not needed: the cloud holds the copy.",
   "Knows where every copy is": "One provider copy; no tracking across your own media.",
   "Removable and offline disks": "No removable-disk workflow.",
   "Licence and price": "Clients AGPL-3.0; free tier and inexpensive paid plans.",
   "Maturity": "Established service.",
  },
  choose="Choose Filen when you want inexpensive, EU-hosted encrypted cloud storage with open-source clients and are happy with one provider holding your off-site copy.",
  varsto="Choose Varsto when the storage itself should be yours to choose and change, when you want copies with several providers and on your own disks, and when you want rules such as \"at least one copy outside the house\" checked for you.",
  sources=[("Filen", "https://filen.io/"), ("Filen pricing", "https://filen.io/pricing"), ("Filen source code", "https://github.com/FilenCloudDienste")]),
 dict(slug="tresorit", name="Tresorit", url="https://tresorit.com/",
  what="Tresorit is end-to-end encrypted cloud storage and file sharing from Switzerland, aimed mainly at businesses and regulated sectors, with personal plans as well. Its clean, careful interface is one of the inspirations for Varsto's own.",
  how="You create an account and files are stored in Tresorit's data centres, with data-residency choices for business customers. Files and relevant metadata are encrypted end to end; keys are shared with public-key cryptography. It offers encrypted share links, version history (the number of versions depends on the plan), remote device wipe and apps for Windows, macOS, Linux, Android, iOS and the web.",
  rows={
   "Where your files live": "In Tresorit's cloud; no own backends.",
   "Account or central server": "Account required.",
   "Encryption": "End-to-end, zero-knowledge; closed source.",
   "Devices online together": "Not needed: the cloud holds the copy.",
   "Knows where every copy is": "One provider copy; no tracking across your own media.",
   "Removable and offline disks": "No removable-disk workflow.",
   "Licence and price": "Proprietary; a small free tier and paid personal and business plans.",
   "Maturity": "Mature commercial service with compliance features.",
  },
  choose="Choose Tresorit when you need a compliant, supported business service with administration, data residency and polished sharing, and a closed-source provider is acceptable.",
  varsto="Choose Varsto when you want comparable end-to-end encryption without a provider in the middle: your own buckets and disks, peer-to-peer transfer between your devices, a record of every copy, and source you can read. Varsto's organisation features (administrators, approvals, removing a person) are new and still alpha.",
  sources=[("Tresorit security", "https://tresorit.com/security"), ("Tresorit personal plans", "https://tresorit.com/pricing/personal")]),
 dict(slug="git-annex", name="git-annex", url="https://git-annex.branchable.com/",
  what="git-annex manages large files with git without storing their contents in git. It is a powerful tool for technical users who archive, back up and move data across many drives and remotes, and it is the closest relative of Varsto on this list.",
  how="Each repository can live on any machine or disk, and \"special remotes\" reach S3 and compatible stores, rclone, rsync, plain or removable directories, WebDAV and more. A git branch records which repository holds each file (\"git annex whereis\"), and numcopies refuses to drop content unless enough verified copies exist elsewhere. Encryption is optional per special remote, using GnuPG; file names in the git repository itself stay visible unless gcrypt is used. It is mainly a command-line tool; there is a simpler assistant, Android works through Termux, and there is no iOS app.",
  rows={
   "Where your files live": "Anywhere you choose: own disks, NAS, S3, other clouds through rclone.",
   "Account or central server": "None.",
   "Encryption": "Optional per special remote (GnuPG); names in the repository visible unless gcrypt is used.",
   "Devices online together": "Not needed; sync is explicit or scheduled rather than continuous by default.",
   "Knows where every copy is": "Yes: location tracking and numcopies, the inspiration for Varsto's ledger and policies.",
   "Removable and offline disks": "Yes: first-class, a disk's contents stay known while it is unplugged.",
   "Licence and price": "Free software (AGPL-3+), free.",
   "Maturity": "Mature, actively released for more than a decade.",
  },
  choose="Choose git-annex when you are comfortable with git and the command line, want maximum control and transparency, and value a mature free-software tool over a ready-made app.",
  varsto="Varsto aims to give the same guarantees (every copy accounted for, rules for how many copies must exist, removable disks that come and go) to people who do not use git: continuous background sync, a desktop and phone interface, encryption that always covers names and contents, peer-to-peer transfer and sharing with other people.",
  sources=[("git-annex", "https://git-annex.branchable.com/"), ("Special remotes", "https://git-annex.branchable.com/special_remotes/"), ("Encryption", "https://git-annex.branchable.com/encryption/"), ("numcopies", "https://git-annex.branchable.com/git-annex-numcopies/")]),
]

def e(s): return html.escape(s, quote=False)

HONEST = ('<p class="note">Varsto is alpha software: do not trust it with data you have no other copy of, '
          'and its cryptography has not been independently audited. The other products here are mature. '
          f'Facts about them were checked from their own documentation in {CHECKED}; prices and plans change often, '
          'so see their own pages for current figures. Corrections are welcome on the <a href="{{P}}forum/">forum</a> or on GitHub.</p>')

for p in P:
    rows = "\n".join(f'      <tr><th scope="row">{e(k)}</th><td>{e(p["rows"][k])}</td><td>{e(VARSTO[k])}</td></tr>' for k in VARSTO)
    src = "\n".join(f'      <li><a href="{u}">{e(t)}</a></li>' for t, u in p["sources"] if u.rstrip("/") != p["url"].rstrip("/"))
    body = f"""---
title: Varsto and {p['name']}
nav: Compare
output: compare/{p['slug']}/index.html
description: What {p['name']} is for, how it works, and how it compares with Varsto.
---
    <p class="back-link"><a href="{{{{P}}}}compare/">All comparisons</a></p>
    <h1>Varsto and {e(p['name'])}</h1>
    <p class="lead">{e(p['what'])}</p>

    <h2>How {e(p['name'])} works</h2>
    <p>{e(p['how'])}</p>

    <h2>Side by side</h2>
    <table class="compare-table">
      <thead><tr><th scope="col"></th><th scope="col">{e(p['name'])}</th><th scope="col">Varsto</th></tr></thead>
      <tbody>
{rows}
      </tbody>
    </table>

    <h2>Which one fits</h2>
    <div class="grid two">
      <div class="card"><h3>{e(p['name'])}</h3><p>{e(p['choose'])}</p></div>
      <div class="card"><h3>Varsto</h3><p>{e(p['varsto'])}</p></div>
    </div>
    {HONEST}

    <h2>Sources</h2>
    <ul>
      <li><a href="{p['url']}">{e(p['name'])} website</a></li>
{src}
    </ul>
"""
    (OUT / f"compare-{p['slug']}.html").write_text(body)

# Overview
heads = "".join(f'<th scope="col"><a href="{p["slug"]}/">{e(p["name"])}</a></th>' for p in P)
keys = ["Where your files live", "Account or central server", "Devices online together", "Knows where every copy is", "Removable and offline disks", "Licence and price"]
SHORT = {
 "syncthing": ["Your devices", "None", "Yes", "No", "No", "Open source, free"],
 "resilio-sync": ["Your devices", "No account", "Yes", "No", "No", "Proprietary, free tier"],
 "mega": ["MEGA's cloud", "Account", "No", "One provider copy", "No", "Plans, client source published"],
 "filen": ["Filen's cloud", "Account", "No", "One provider copy", "No", "Plans, open-source clients"],
 "tresorit": ["Tresorit's cloud", "Account", "No", "One provider copy", "No", "Proprietary plans"],
 "git-annex": ["Anywhere you choose", "None", "No", "Yes", "Yes", "Free software, free"],
}
VSHORT = ["Your devices and your storages", "None", "No", "Yes", "Yes", "Source-available, free"]
LABEL = {"Devices online together": "Devices must be online together"}
trs = []
for i, k in enumerate(keys):
    cells = "".join(f"<td>{e(SHORT[p['slug']][i])}</td>" for p in P)
    trs.append(f'      <tr><th scope="row">{e(LABEL.get(k, k))}</th><td><strong>{e(VSHORT[i])}</strong></td>{cells}</tr>')
cards = "\n".join(f'      <a class="card" href="{p["slug"]}/"><h3>Varsto and {e(p["name"])}</h3><p>{e(p["what"].split(". ")[0].rstrip("."))}.</p></a>' for p in P)
overview = f"""---
title: Compare
nav: Compare
output: compare/index.html
description: How Varsto compares with Syncthing, Resilio Sync, MEGA, Filen, Tresorit and git-annex: what each is for and where they differ.
---
    <h1>How Varsto compares</h1>
    <p class="lead">Tools for keeping files in sync fall into three groups. Peer-to-peer tools such as Syncthing and Resilio Sync copy folders between your own devices. Encrypted clouds such as MEGA, Filen and Tresorit keep your files with one provider. git-annex tracks large files across any disks and remotes you own. Varsto combines parts of all three: end-to-end encrypted files on storages you choose, peer-to-peer transfer between your devices, and a record of where every copy is.</p>

    <table class="compare-table compare-overview">
      <thead><tr><th scope="col"></th><th scope="col">Varsto</th>{heads}</tr></thead>
      <tbody>
{chr(10).join(trs)}
      </tbody>
    </table>
    <p class="note">"One provider copy" means the off-site copy is with that provider; your devices keep their own copies too. Each comparison page explains the details and links to the sources.</p>

    <h2>Comparisons</h2>
    <div class="grid three">
{cards}
    </div>
    {HONEST}
"""
(OUT / "compare.html").write_text(overview)
print("written")
