---
title: Alpha.12: pienet tiedostot paketeissa, ja Varsto suomeksi ja ruotsiksi
date: 2026-10-12
summary: Pienet salatut lohkot kirjoitetaan nyt paketteihin, joten 20 000 pienen tiedoston kansiosta tulee ämpäriin 79 objektia 20 000:n sijaan. Käyttöliittymä, ilmoitusalue, valikkorivi, mobiilikuoret ja tämä sivusto ovat saatavilla suomeksi ja ruotsiksi sekä englanniksi.
---
Alpha.12:ssa on kaksi teemaa: vähemmän objekteja tallennuspaikassasi, ja käyttöliittymä useammalla kielellä.

## Pienet lohkot paketeissa

Tähän asti jokainen salattu lohko oli oma objektinsa tallennuspaikassa. Se on yksinkertaista ja vankkaa, mutta kansio jossa on paljon pieniä tiedostoja, kuten muistiinpanoja, lähdekoodia tai valokuvakirjaston oheistiedostoja, muuttuu kymmeniksi tuhansiksi pikkuruisiksi objekteiksi. Moni palveluntarjoaja veloittaa pyynnöittäin, jotkut objekti kerrallaan, ja kaikkien listaaminen ja tarkistaminen on hidasta.

Tästä versiosta alkaen enintään 128 KiB:n lohkot kootaan noin 4 MiB:n tai 256 jäsenen paketteihin. Paketti kirjoitetaan hakemiston kanssa, joka nimeää jäsenensä ja sen, mistä kukin alkaa, ja jäsen luetaan aluepyynnöllä, joten yhden pienen tiedoston lukeminen lataa yhä vain sen omat tavut. Suuret lohkot kirjoitetaan yhä yksi kerrallaan. Paketteja käytetään S3-ämpäreissä, rclone-etäkohteissa ja hakemistoissa; kylmätallennus, levyvarastot ja siirtolevyt pitävät yksittäisiä objekteja.

Laboratoriossa 20 000 pienen tiedoston kansio meni ämpäriin 79 pakettina 20 000 objektin sijaan. Jokainen jäsen tarkistettiin nimeään vasten ajon jälkeen.

Paketissa olevan lohkon poistaminen kirjoittaa pienen poistomerkin, ja itse paketti poistuu, kun jokainen jäsen on poissa. Korjaus, tarkistus, replikat, datan siirrot ja tallennuspaikan poistaminen ymmärtävät kaikki paketit. Tallennusmuoto on kuvattu [muodon määrittelyn](../docs/alpha-0-format.html) kohdassa 30.

Yhteensopivuutta vanhempien versioiden kanssa ei ole: laite, joka on versiossa alpha.11 tai vanhemmassa, ei näe paketeissa olevia lohkoja. Päivitä jokainen laite.

## Matkan varrella löytyneet korjaukset

Laboratorioajot löysivät ongelmia, jotka yksikkötestit olivat ohittaneet:

- `rclone serve s3` vastaa aluelukuun tilakoodilla 200 ja vain pyydetyillä tavuilla. Varsto hyväksyy sen nyt myös tavallisen 206:n lisäksi, joten paketit luetaan oikein tällaisilta palvelimilta.
- Laite, joka oli juuri lukenut pakettien hakemistot, ei katsonut uudelleen paketteja, jotka toinen laite kirjoitti hetkeä myöhemmin. Haku, joka ei löydä, lataa hakemistot nyt heti uudelleen.
- Laite saattoi luottaa paketin hakemistoon sen jälkeen, kun toinen laite oli poistanut siitä jäseniä. Ennen kuin Varsto päättää, että lohko on jo olemassa eikä sitä tarvitse kirjoittaa, se tarkistaa nyt että lohko on yhä paketissaan.
- Levyvarastot ja muut tallennuspaikat, joissa ei ole paketteja, kirjoittavat lohkonsa taas yksi kerrallaan, joten täysi tai puuttuva levy ilmoitetaan sellaisenaan eikä koko työntö epäonnistu.
- S3-palvelin, jonka kello on enemmän kuin muutaman minuutin pielessä, korjataan nyt molempiin suuntiin, myös kun se vastaa tilakoodilla 400 eikä 403.

## Suomi ja ruotsi

Työpöytäkäyttöliittymä, ilmoitusalue ja macOS:n valikkorivi, Android- ja iOS-kuoret sekä tämä sivusto ovat nyt saatavilla suomeksi ja ruotsiksi. Englanti pysyy oletuksena. Kieli valitaan käyttöliittymän asetuksista tai sivupalkin alareunasta, ja ilmoitusalue ja sovellukset seuraavat samaa valintaa. Komentorivi, dokumentaatio ja kaikki tietovarastossa pysyvät englanniksi.

Turvallisuuden kannalta kriittisten tekstien käännökset, kuten ne jotka koskevat poistamista, laitteiden kumoamista ja palautussanoja, on merkitty äidinkielisten tarkistettaviksi. Korjaukset ovat tervetulleita.

## Rakenna Varstoa kanssamme

Uusi [Osallistu](../contribute/) -sivu kertoo, miten Varsto rakennetaan ja missä apua kaivataan: kryptografian ja tallennusmuodon katselmointi, Windows, iOS ja Android, NAT-läpäisy muissa verkoissa kuin ylläpitäjän, lisää S3-palveluntarjoajia, paketointi ja käännökset.
