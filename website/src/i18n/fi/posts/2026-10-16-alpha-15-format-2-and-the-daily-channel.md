---
title: Alpha.15: tallennusmuoto 2, Windowsin asennusohjelma ja päivittäinen kanava
date: 2026-10-16
summary: Uusi tallennusmuoto, joka korjaa kaksi tietoturvakatselmoinnin löydöstä, joten olemassa olevat holvit on luotava uudelleen; Windows saa asennusohjelman, oman ikkunan ja automaattiset päivitykset; sekä allekirjoitettu päivittäisten versioiden kanava.
---
Nykyinen julkaisu on [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Tämä teksti kuvaa vanhempaa julkaisua. [Lataukset](https://varsto.net/downloads/) antavat version alpha.17, ja lähdekoodi on [GitHubissa](https://github.com/janttsu/varsto).

Alpha.15 muuttaa tallennusmuodon. Tämä pitää tietää ennen päivitystä: alpha.14:n tai sitä vanhemman tekemää holvia tämä versio ei avaa, vaan holvi on luotava uudelleen. Julkaisun loppu on pitkä lista korjauksia ja käyttöliittymätyötä, kunnollinen Windows-asennus ja päivittäisten versioiden kanava ihmisille, jotka haluavat kokeilla uusinta koodia.

## Muoto 2 ja mitä se tarkoittaa

Alpha.14:n taustalla ollut tietoturvakatselmointi löysi kaksi ongelmaa siinä, miten lohkot tallennettiin, eikä niitä voinut korjata muuttamatta muotoa. Muoto 2 korjaa ne:

- Salatun lohkon nonce johdetaan nyt täsmälleen niistä tavuista, jotka salataan (pakkauksen jälkeen), ei selvätekstistä. Ennen nonce riippui pakkaustuloksesta, jonka samaa tulosta eri zstd-versiot eivät taanneet.
- Pilkkoja avainnetaan kansiokohtaisesti. Katkaisukohdat olivat ennen tiedoston sisällön julkinen funktio, joten tallennuspaikka, joka tunsi tiedoston, saattoi tunnistaa sen lohkojensa koosta. Nyt sama tiedosto kahdessa kansiossa katkaistaan eri kohdista.
- Jokainen lohko tallennetaan pakettiin (64 MiB, kylmätallennuksessa 256 MiB), eikä yksikään lohko ole oma objektinsa, joten tallennuspaikka näkee pakettien koot, ei niiden sisällä olevien lohkojen kokoja eikä määrää. Paketeilla on salatut hakemistot, ja poistettuja lohkoja seurataan kansiokohtaisesti ja ne kirjoitetaan pois.
- Pakkaus on zstd:n taso 3 nopean kokeilun jälkeen: teksti pakkautuu lähes yhtä hyvin kuin ennen ja kirjoittuu monin verroin nopeammin.

Mitä muoto 2 ei korjaa: tiedostoluettelot ja jakokaudet hyväksytään yhä pelkällä kansioavaimella, koska sen sulkeminen vaatii allekirjoitetut tiedostoluettelot ja jakokaudet, jotka kuuluvat seuraavan muodon tietuekerrokseen. Kunnes se on olemassa, kansion avaimen haltija voi yhä muuttaa sitä, mitä kansio näyttää, ja epäluotettavia replikoita ja jaettuja kansioita tulee kohdella sen mukaisesti. Molemmat kriittiset löydökset ovat yhä auki versiossa alpha.15.

**Holvin luominen uudelleen.** Siirtoa ei ole. Alpha.15 hylkää vanhemman holvin avatessaan sen tai kun laite liittyy sen tallennuspaikan kautta, ja viesti sanoo, mitä tehdä. Pidä tiedostosi siellä missä ne ovat, ja sitten:

1. Pidä alpha.14:n binääri tallessa siltä varalta, että joudut lukemaan vanhan holvin.
2. `varsto reset --yes` laitteella, sitten `varsto init`.
3. Lisää tallennuspaikat uudelleen ja synkronoi kansiot.

Alpha.14 hylkää muodon 2 holvin samalla tavalla, joten nämä kaksi versiota eivät voi jakaa holvia kumpaankaan suuntaan.

## Windows: asennusohjelma, oma ikkuna ja automaattiset päivitykset

Siirrettävä zip on poissa. Windowsilla on nyt yksi lataus, `Varsto-<version>-setup.exe`: se päivittää paikalleen, osaa korjata asennuksen, ja asennuksen poisto säilyttää datakansiosi. Käyttöliittymä avautuu omassa ikkunassa (WebView2), koko ja paikka muistetaan, yksi ikkuna käyttäjää kohden, ja ilmoitusalue käynnistää sen. Asennusohjelmalla asennetut kopiot tarkistavat päivitykset kerran päivässä, tarkistavat allekirjoitetun asennusohjelman ja asentavat sen hiljaa. Jos ajat yhä purettua siirrettävää kopiota, `varsto update` kehottaa ajamaan asennusohjelman kerran; sen jälkeen päivitykset jatkuvat itsestään.

## Kaikki muu alpha.14:n jälkeen

- Kansion yleiskatsaus, jossa on turvallisuusosoitin kansiota kohden: 100 % ulkoisessa tallennuspaikassa, 100 % vain omilla levyilläsi, osittain suojattu tai vain laitteilla.
- Laitteiden, tallennuspaikkojen, levyjen ja pilven elävä visualisointi, jossa virrat liikkuvat, ja oikea koko näyttö selaimessa sekä Android-, macOS- ja Windows-kuorissa (Esc poistuu).
- Edelleenlähetys: kansioon liitetty laite, myös valikoivalla synkronoinnilla, voi kuljettaa muiden laitteiden lohkoja tallennuspaikkoihin, joihin se voi kirjoittaa, joten puhelimen kuvat päätyvät ämpäriin, jonka tunnukset ovat vain kannettavalla. Liittämisen valintaikkuna kysyy nyt täyttä tai valikoivaa synkronointia ja suuntaa.
- Pariutuminen tarjoaa jokaisen käyttökelpoisen paikallisen osoitteen, paras ensin, ja liittyminen kokeilee niitä vuoron perään ja lähiverkon hakua, näkyvällä edistymisellä ja virheellä, joka nimeää kokeillun.
- Uusi data saa armonajan, ennen kuin tarkistus ilmoittaa rikkomuksesta: lohkot, jotka on tallennettu sen ajan sisällä, joka on suurempi tarkistusikkunasta ja 24 tunnista, näkyvät tilassa ”tarkistus odottaa”.
- Käyttöliittymä pysyy käytettävänä pitkien synkronointien ajan: kun palvelu on kiireinen, lukuihin vastataan viimeksi säilytetystä vastauksesta, luettelot piirretään vähitellen, eikä sivua ladata koskaan uudelleen.
- Korjaukset: tyhjennys ja sijoittelu kieltäytyvät nyt ristiriitaisista valinnoista, esikatselukuvat myöhemmin lisätyille tallennuspaikoille, puhelimet hyväksyvät vain S3- ja rclone-tallennuspaikat, puhelimessa jo olevat kuvat ja videot varmuuskopioidaan uusimmasta alkaen, palautuspaketin tulostaminen, macOS:n Dock-kuvake, Androidin Takaisin-painike ja näppäimistö, `reset` ja palvelun uudelleenkäynnistykset sekä levyaseman alustus nykyaikaisella GPT-asettelulla.
- Allekirjoittamaton iOS-`.ipa` AltStorea, SideStorea ja Sideloadlya varten.
- Sivustolla on ranskan käännös, ja suomen- ja ruotsinkieliset sivut näyttävät kuvakaappaukset käyttöliittymästä omalla kielellään.

## Päivittäinen kanava

`varsto update --daily` asentaa päähaaran uusimman päivittäisen version. Päivittäiset versiot tehdään kaikille alustoille aina kun päähaara liikkuu, ja ne julkaistaan osoitteessa varsto.net/daily/. Tarkistussummaluettelo allekirjoitetaan päivittäisellä avaimella, joka on erillään julkaisuavaimesta: päivitysohjelma luottaa kuhunkin avaimeen vain sen omalla kanavalla, joten päivittäinen allekirjoitus ei koskaan kelpuuta julkaisua, eikä toisin päin. Se hylkää myös luettelot, jotka ovat vanhentuneita, tulevaisuudesta tai vanhempia kuin ajamasi käännös. Taustalla toimiva päivitys ja käyttöliittymä pysyvät julkaisuissa; päivittäinen kanava käynnistetään aina vain käsin.

Päivittäiset versiot ovat kehitysversioita. Ne eivät ole tuotantodatalle, ja päivittäinen versio voi tuoda tallennusmuodon muutoksen ennen kuin yksikään julkaisu tekee niin.

## Yhteensopivuus

Holvin jokaisen laitteen on oltava versiossa alpha.15. Alpha.14 ei voi lukea alpha.15:n holvia eikä alpha.15 alpha.14:n holvia, eikä kumpikaan lue toisen paketteja eikä poistomerkkiluetteloita. Päivitä kaikki laitteet yhdessä ja luo holvi uudelleen yllä kuvatulla tavalla.
