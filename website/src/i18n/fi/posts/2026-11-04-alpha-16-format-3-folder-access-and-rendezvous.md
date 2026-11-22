---
title: Alpha.16: tallennusmuoto 3, kansion käyttöoikeus hyväksynnällä ja kohtaamispalvelu
date: 2026-11-04
summary: Uusi tallennusmuoto, jossa on pakettitason kirjanpito, allekirjoitetut tietueet ja palautussanat, joten olemassa olevat holvit on luotava uudelleen; kansio avataan laitteelle omistajan hyväksynnällä; laitteet löytävät toisensa valinnaisen kohtaamispalvelun kautta; liittyminen ja jäsenyyden muutokset toimivat ilman yhteyttä; sekä tuonnit torrenteista ja YouTubesta.
---
Nykyinen julkaisu on [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Tämä teksti kuvaa vanhempaa julkaisua. [Lataukset](https://varsto.net/downloads/) antavat version alpha.17, ja lähdekoodi on [GitHubissa](https://github.com/janttsu/varsto).

Alpha.16 muuttaa tallennusmuodon jälleen. Tämä pitää tietää ennen päivitystä: alpha.15:n tai sitä vanhemman tekemää holvia tämä versio ei avaa, vaan holvi on luotava uudelleen. Julkaisun loppu on pitkä lista muutoksista siinä, miten laitteet liittyvät, löytävät toisensa ja selviävät huonosta verkosta, uusi Tuonti-sivu sekä suuri joukko korjauksia ja kovennusta uuden muodon katselmoinnista.

## Holvin luominen uudelleen

Siirtoa ei ole. Alpha.16 hylkää vanhemman holvin avatessaan sen tai kun laite liittyy sen tallennuspaikan kautta, ja viesti sanoo, mitä tehdä. Alpha.15 hylkää muodon 3 holvin samalla tavalla, joten nämä kaksi versiota eivät voi jakaa holvia kumpaankaan suuntaan. Holvin jokaisen laitteen on oltava versiossa alpha.16. Pidä tiedostosi siellä missä ne ovat, ja sitten:

1. Pidä alpha.15:n binääri tallessa siltä varalta, että joudut lukemaan vanhan holvin.
2. `varsto reset --yes` laitteella, sitten `varsto init`. Se tulostaa paketin, jossa on kaksi sanajoukkoa: holvisanat ja, uutena muodossa 3, palautussanat. Säilytä molemmat.
3. Lisää tallennuspaikat uudelleen, lisää kansiot (palautussanoja kysytään tässä) ja synkronoi.

## Android: poista vanha APK ensin

Android-paketti on nyt julkaisuallekirjoitettu APK (`varsto-<version>-android.apk`), ei debug-käännös, joten myöhempi julkaisu asentuu sen päälle päivityksenä. Se on allekirjoitettu uudella avaimella. Aiempaa debug-APK:ta (alpha.15 tai vanhempi päivittäinen versio) ei voi päivittää siihen: Android kieltäytyy päivityksestä. Poista vanha sovellus ensin ja asenna sitten uusi. Asennuksen poisto poistaa sen laitteen holvikopion, joten varmista ennen sitä, että holvilla on toinen laite tai tallennuspaikka. Päivittäinen Android-lataus pysyy debug-käännöksenä nimellä `varsto-daily-android-debug.apk`.

## Tallennusmuoto 3

Muoto 3 on kuvattu määrittelyn kohdassa 77 ja muodon 3 suunnitteludokumentissa. Mitä se muuttaa sinulle:

- Kirjanpito ei enää luettele jokaista lohkoa. Se väittää paketteja, joilla on yksi muutamasta kiinteästä koosta (256 KiB–64 MiB, täytettynä), joten tallennuspaikka näkee kokoluokat, ei sitä montako lohkoa tai tiedostoa on.
- Jokainen julkaistu objekti pakettia lukuun ottamatta on allekirjoitettu tietue, joka nimeää avaimen, jolla se on sinetöity. Tiedostoluettelot, roskakorin luettelot ja tilannevedokset ovat pohja ja pieniä deltoja, ja jokainen kansio pitää allekirjoitetun lohkokartan kutakin kirjoittavaa laitetta kohden.
- Kansioavain päätyy laitteelle vain myöntönä, jonka omistaja on hyväksynyt. Holvisanoilla liittyvä laite näkee kansioiden nimet eikä saa sisältöä; se pyytää komennolla `varsto folder request`, omistaja vertaa kuutta sanaa, jotka näkyvät molemmilla laitteilla, ja hyväksyy komennolla `varsto folder approve` (myös `requests`, `deny`, `members`, `role`). Taustapalvelu ei koskaan hyväksy. Käyttöliittymässä on Kansioiden käyttöoikeudet -kortti Tiedostot-sivulla.
- Jokaisella kansioavaimen kaudella on palautuskopio palautussanojen alla. `varsto folder add` tekee sen, `varsto recovery escrow` kirjoittaa puuttuvan myöhemmin, ja `varsto status` varoittaa siihen asti. `varsto join --recovery-words` avaa jokaisen kansion, jolla on palautuskopio.
- Vertaiset puhuvat vain TLS:ää, tunnisteilla jotka on sidottu yhteyteen, ja vertaavat kirjanpidon päitä, joten tallennuspaikka, joka pidättää eriä tai kelaa niitä taaksepäin, huomataan, ja Ohje-sivu sekä ilmoitus kertovat siitä.
- Laitteen poistaminen pysyy nyt: kumottu laite ei saa seuraavaa kansioavainta, ja sen tietueet lakkaavat laskemasta poistosta.

## Toistensa löytäminen: kohtaamispalvelu

Laitteet voivat löytää toisensa verkkojen yli valinnaisen kohtaamispalvelun kautta, oletuksena `https://varsto.net/rv`. Laite jättää sinne sinetöidyn vertaistietueensa, lukee holvin tietueet, saa tietää oman julkisen osoitteensa ja, kun mikään osoite ei vastaa, tavoittaa vertaisen koordinoidulla reiänlyönnillä tai viimeisenä reittinä päästä päähän salatulla välityksellä (näkyy muodossa `relayed via rendezvous`). Liittyvä laite, joka ei löydä verkostaan mitään, voi hakea tarjouksen koodilla tai linkillä ja pariutua välityksen kautta. Palvelu näkee tunnisteita, IP-osoitteita ja tavumääriä, ei koskaan holvin identiteettiä eikä sisältöä. `varsto p2p rendezvous set <url> | on | --off | status` tai Vertaiset-sivu muuttaa sitä, ja palvelimen voi pitää itse (`varsto-rendezvous`, staattinen Linux-binääri päivittäisessä versiossa; oletus-UDP-portti on 3334). Kaikki toimii myös ilman sitä.

## Huono verkko ja työ ilman yhteyttä

- Yksi tallennuspaikka, johon ei saada yhteyttä, ei enää kaada koko synkronointia. Se merkitään alhaalla olevaksi ajon ajaksi ja lepää ajojen välillä, ja muut tallennuspaikat jatkavat; se minkä se missasi kopioidaan sinne myöhemmin.
- S3- ja rclone-kutsuilla on aikarajat, jotka sopivat siirron kokoon, uudelleenyritykset ja jatkettavat moniosaiset lähetykset, joten hidas yhteys maksaa sekunteja, ei minuutteja.
- Vertaisyhteys toimii ilman yhtään tallennuspaikkaa, tallennetusta vertaishakemistosta, joten lähiverkon synkronointi toimii ilman internetiä.
- Liittyminen pariutumalla ei enää tarvitse tallennuspaikan vastausta, ja jäsenyyden muutokset (kansion lisääminen, hyväksyminen, roolin muuttaminen, jakaminen) pidetään ensin laitteella ja lähetetään, kun tallennuspaikka vastaa. `varsto status` kertoo, montako muutosta odottaa lähetystä: ”N changes waiting to upload”.
- Paikalliset toimet (tuonnit, Roskakori-sivu, esikatselukuvat, tiedostojen kirjoitukset) valmistuvat, kun tallennuspaikka on alhaalla, ja ilmoittavat, että lähetys odottaa: ”upload pending”.
- Käyttöliittymä, ilmoitusalue, komentorivi ja MCP eivät enää jumitu, kun synkronointi odottaa kuollutta yhteyttä.

## Tuonnit

- Yksi Tuonti-sivu jokaiselle lähteelle (kansio tai levy, git-annex-tietovarasto, pilviasema rclonen kautta, torrent, YouTube), ja luettelo käynnissä olevista tuonneista.
- `varsto import torrent` tuo levyä suurempia torrentteja erissä, jotka pitävät vapaan tilan varauksen; tiedosto lähtee latauslevyltä vasta, kun sen lohkot ovat tallennuspaikassa ja kansion sääntö pätee.
- `varsto import youtube` arkistoi kanavat, soittolistat ja videot kansioihin yt-dlp:llä, kohteliain oletuksin ja vapaan tilan varauksella.

## Levyt ja palvelimet

- `varsto mailbox` puskuroi lohkot telakoidulta levyltä levyvaraston levylle tai tallennuspaikalle, joka on poissa, kestävään, tiivisteellä tarkistettuun lähtölaatikkoon, joten lohko joka on vain levyllä A päätyy levylle B, kun B telakoidaan.
- `varsto service remember` toimii ilman työpöytäistuntoa (SSH:n yli, palvelimilla) `systemd-creds`-palvelun tai ytimen avainnipun kautta; `varsto service forget` poistaa sen.
- `varsto service stop` pysyy nyt pysäytettynä, ja itsepäivitys käynnistää palvelun yhä uudelleen.

## Korjaukset ja kovennus

- Haku ei enää korvaa tiedostoa, jota on muokattu skannauksen jälkeen, eikä yksi huono tiedosto enää pysäytä kansion hakua tai työntöä. Lukukelvoton tiedosto tai hakemisto lasketaan, sen sijaan että sen alla olevat tiedostot näyttäisivät poistetuilta.
- Jäsenyys: laitteen poisto pätee myöhempiin liittyjiin ja kansioihin, joita ei avainnettu uudelleen, ja vain ylläpitäjän kausi, kumous tai tyhjennys otetaan käyttöön.
- Tyhjennys, tallennuspaikan poistaminen ja siivous levyn liittämisen jälkeen säilyttävät jokaisen paketin, joka saattaa olla ainoa kopio. Korjaus, työntö puuttuvan erän jälkeen ja liittäminen irrottamisen jälkeen on korjattu.
- S3:n aluehaut eivät enää saa `fsck`:tä pitämään jokaista pakettia lyhyenä.
- Visualisointi näyttää lataushuomautuksen tai tyhjän holvin huomautuksen esimerkkikuvan sijaan, ja esikatselukuvat näkyvät sivulla.
- TLS-kättelyillä on aikaraja, joka pitää, ja osoitteella voi olla enintään 64 keskeneräistä. Jumittunut paikallinen asiakas ei voi enää jäädyttää paikallista rajapintaa. Kohtaamispalvelimella on nopeusraja pyyntöluokkaa kohden ja rajattu muisti hauille. `cargo audit` -ohjelman raportoimat riippuvuusvaroitukset on paikattu.
- GitHub-työnkulut ajetaan vain luku -oikeuksin, paitsi siellä missä ne julkaisevat.

## Yhteensopivuus

Holvin jokaisen laitteen on oltava versiossa alpha.16. Alpha.15 ei voi lukea alpha.16:n holvia eikä alpha.16 alpha.15:n holvia. Päivitä kaikki laitteet yhdessä ja luo holvi uudelleen yllä kuvatulla tavalla. Tämä on yhä alfa: ei tuotantodatalle. Koko lista on muutoslokissa.
