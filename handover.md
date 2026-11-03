# Varsto handover 2026-11-03

Integraatiohaara on `integrate/review-20261031`.
Sitä ei ole mergetty `main`-haaraan. Releasea ei ole tehty.

Julkaistu daily on yhä commitista `dae29628`
(`dae296281a88eff2bccf5473d8b4e2ae13fe9640`).
Tagi `daily`, julkaisu "Daily build 20261028-dae2962",
julkaistu 2026-10-28 19:08 UTC.
2.11.2026 aikataulutettu ajo
[41429125275](https://github.com/janttsu/varsto/actions/runs/41429125275)
onnistui 4 minuutissa, koska `main` ei ollut liikkunut:
build, ipa ja paketointi jäivät väliin. Uutta dailya ei syntynyt.

Katselmushaaran daily-ajot käynnistettiin `publish=false`.
Ne eivät ole korvanneet tagia `daily`. Viimeisin niistä käytti
koodicommitia `8ed2c84b`. Tämä tiedosto on sen jälkeisissä
handover-commiteissa.

Notion-lähde: Laaja koodikatselmus 2026-10-30, sivu
`409c3713-dc2e-8125-b280-cafc44804c80`, main `dae29628`.
Clauden committoimattomia työpuun tiedostoja (kuvakaappaukset,
`website/public`, `wt-daily`) ei ole otettu mukaan.

## Haarat

Jokainen löydösryhmä on omassa haarassaan `origin/main`-kannasta.
Integraatiohaara yhdistää ne ja lisää daily-käännöksen korjaukset,
joita ei ole cherry-pickattu takaisin yksittäisiin haaroihin.

| Haara | Kärki | Mitä |
|---|---|---|
| `integrate/review-20261031` | `8ed2c84b` ja sen jälkeinen handover | kaikki alla olevat, plus daily-käännöksen korjaukset |
| `fix/engine-pull-safety` | `3d9bcdcb` | ENGINE-1…3 |
| `fix/disks-insert-cleanup` | `56fa052f` | disks-1 |
| `fix/membership-revocation` | `05f8d50e` | membership-1…4 |
| `fix/supplychain-daily-ci` | `54345329` | supplychain-1…2 |
| `fix/ledger-watermarks` | `253603ef` | LEDGER-1…2 |
| `fix/storage-drain-copies` | `b3e9552d` | STORAGE-1 |
| `fix/p2p-handshake-limit` | `bcc60541` | p2p-1 |
| `fix/localapi-timeouts` | `c6ed1d3d` | LOCALAPI-1, vendoroitu tiny_http |
| `fix/cli-service-stop` | `a026350c` | CLI-1 |
| `fix/rendezvous-limits` | `e6f85310` | rendezvous-1…2 |
| `fix/android-release-apk` | `c7f7a737` | mobile-1 |

Integraatiohaaran lisäcommitit `8ed2c84b`-kärjen alla, joita ei ole
`fix/`-haaroissa:

- `97855d4d` clippy-tyyppialias, ffi:n `libc` kaikille Unixeille, AndroidX-riippuvuudet takaisin
- `84aaec04` macOS ei käytä Linuxin `SOCK_CLOEXEC`-socketia
- `86dfc24c` daily-workflow kutsuu CI:tä `secrets: inherit`
- `e57fb48f` stall-testi ei vaadi pientä receive-ikkunaa macOS:lla
- `8ed2c84b` karsitun ledger-etuliitteen yli saa yhä pushata myöhemmän erän; vesileima etenee vain yhtenäistä etuliitettä

## Daily-binäärit

Ajo: https://github.com/janttsu/varsto/actions/runs/41430736340
Commit `8ed2c84b`. `publish=false`.

- Android: tehty. Artefakti `packages-android`, noin 70 Mt.
  Release-allekirjoitettu APK. Julkinen nimi daily-listassa on yhä
  `varsto-daily-android-debug.apk`, koska nimen vaihto rikkoisi
  allekirjoitetun listan. Tavut eivät ole debug-build.
  Keystore on tässä koneessa
  `~/.config/varsto-release/varsto-android.keystore` (PKCS12, alias
  `varsto`). Salasana on samassa hakemistossa, tiedosto
  `varsto-android.password`, oikeudet 600. GitHub-salaisuudet:
  `VARSTO_ANDROID_KEYSTORE` (base64), `VARSTO_ANDROID_KEYSTORE_PASSWORD`,
  `VARSTO_ANDROID_KEY_ALIAS`, `VARSTO_ANDROID_KEY_PASSWORD`.
  Tämä on uusi avain. Vanha debug-asennus ei päivity sen päälle.
- Linux: ei tehty daily-pakettina. Testi
  `share_roles::a_viewer_reads_and_its_own_changes_stay_here`
  kaatui: toisen synkan jälkeen `plan.txt` puuttuu, odotettiin
  jaettua sisältöä `the plan`. Clippy, fmt ja cargo-deny menivät läpi.
  Paikallinen glibc-release aiemmasta käännöksestä ei ole tämä commit
  eikä musl-daily. Käännöshakemisto on siivottu.
- macOS: ei tehty. Ajo ei saanut Apple Silicon -runneria
  (`The job was not acquired by Runner`). Aiempi ajo, joka sai
  runnerin, kaatui ledger-testiin
  `s2_restores_own_checkpoint_after_pruning`. Se on korjattu
  commitissa `8ed2c84b`, mutta sitä ei ole ajettu macOS:lla.

`main` on yhä `dae29628`. Aikataulutettu daily `main`-haarasta ei
sisällä näitä korjauksia.

## Avoinna

- Linux-testi `share_roles` ja sen jälkeen macOS-jobin uusinta-ajo,
  jotta daily-paketit syntyvät. Sitten vasta `publish=true`, jos
  julkinen daily-kanava halutaan vaihtaa.
- Branch protection `main`-haaralle ja daily-avaimen suojattu
  Environment GitHubin asetuksiin. Työnkulku ei tee sitä.
- Jäsenyyden jäljellä olevat reiät: seq-katon alle jäävä aukko,
  `Membership::join` ilman ylläpitäjälistaa, toisen holvin jäsen
  ei sovella rekisterikattoa. Jo jaettua avainta ei voi perua (spec 21).
- iOS-simulaattori peruuntui samassa ajossa, koska runneria ei saatu.
  Allekirjoittamaton ipa sen sijaan valmistui: artefakti
  `Varsto-ios-unsigned`, noin 13 Mt. Sitä ei pyydetty tähän tarkistukseen.
