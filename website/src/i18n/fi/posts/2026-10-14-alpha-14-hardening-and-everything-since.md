---
title: Alpha.14: tietoturvakatselmointi, sen korjaukset ja kaikki mikä on yhdistetty alpha.13:n jälkeen
date: 2026-10-14
summary: Koko ohjelman tietoturvakatselmointi koodin tasolla, sen pyytämät korjaukset, paljon nopeampi synkronointi, jatkettavat siirrot irrotettavien levyjen pinoon ja parikymmentä ominaisuutta, jotka olivat odottaneet päähaarassa alpha.13:sta asti.
---
Nykyinen julkaisu on [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Tämä teksti kuvaa vanhempaa julkaisua. [Lataukset](https://varsto.net/downloads/) antavat version alpha.17, ja lähdekoodi on [GitHubissa](https://github.com/janttsu/varsto).

Alpha.14 on tähän asti suurin julkaisu. Siinä on kaksi asiaa: ominaisuuksien rästi, joka tuli päähaaraan alpha.13:n jälkeen, ja ensimmäinen kierros korjauksia tietoturvakatselmoinnista, joka luki ohjelman jokaisen rivin sillä oletuksella, että tallennuspaikka, verkko ja toinen laite voivat olla vihamielisiä.

## Tietoturvakatselmointi

Katselmointi piti kryptografisia primitiivejä kunnossa olevina ja valtuutusta niiden ympärillä puutteellisena. Alpha.14 sulkee ne kohdat, jotka voitiin sulkea muuttamatta tallennusmuotoa:

- Kirjanpidon tapahtumat hyväksytään roolin mukaan: replika saa väittää vain kopioita, jaetun kansion jäsen saa puhua vain tuosta kansiosta, ja tarkistuspisteet otetaan vain täysiltä laitteilta. Tallennuspaikka, joka pidättää erän, huomataan, laitteen oman nimen alle kirjoitettu roskaobjekti ei enää sulje laitetta ulos, ja kumous lasketaan vain yhdessä allekirjoitetun avainkautensa kanssa.
- Palvelu ja vertaiskuljetus: STUN-sivukanava on rajattu, selain saa kertakäyttöisen aloituskoodin istuntotunnisteen sijaan, tarkoin laadittu pyyntö ei voi enää kaataa rajapintaa, Strongroom-avainten on täsmättävä sitoumukseen ja suojausavain kysyy PIN-koodiaan, salaisuudet on poistettu komentoriviltä, päivitysohjelma hylkää vanhentuneet allekirjoitetut luettelot, ja tallennuspaikan luvut on rajattu.
- Hygienia: avaintiedostot luodaan yksityisiksi heti ensimmäisestä tavusta, tunnisteita verrataan vakioajassa, avainmateriaali pyyhitään muistista, palautusosuuksissa on tarkiste, ja Shamir-kirjasto vaihdettiin korjattuun haaraan.

Kaksi löydöstä tarvitsee uuden tallennusmuodon, eivätkä ne ole tässä julkaisussa: tiedostoluettelot ja jakokaudet hyväksytään yhä pelkällä kansioavaimella, ja palan nonce tulee yhä selvätekstistä. Molemmat on rakennettu muodon 2 haaroille, joka on seuraava julkaisu. Siihen asti kohtele jaettuja kansioita ja epäluotettavia replikoita niin kuin katselmointi kuvaa: kansion avaimen haltija voi yhä muuttaa sitä, mitä kansio näyttää.

## Nopeampi

50 000 pienen tiedoston synkronointi paikalliseen tallennuspaikkaan vei 167 sekunnin sijaan 21; 10 000 tiedostoa 77:n sijaan 8,5. Kelloa ei enää kirjoiteta levylle tiedosto kerrallaan, tallennuspaikat avataan kerran synkronointia kohden, lähetykset hajautuvat tallennuspaikoittain, S3-asiakas kokeilee kerran noudatetaanko ehdollisia kirjoituksia, ja binäärit käännetään linkkiaikaisella optimoinnilla ja nopeammalla muistivaraajalla.

## Kaikki alpha.13:n jälkeen

Reaaliaikainen toiminta laitteiden välillä, bittimätätarkistus, kokonaiset asemat levyvarastoihin, varmuuskopiot resticillä, tiedostoanalyysit ja `varsto search`, rajatut MCP-avaimet, kirjanpidon uudelleenrakennus, mediasta tietoinen tarkistus, levyjen kirjanpito ja ”seuraava telakoitava levy”, palautuspaketin opas, tuonnit git-annexista, pilviasemista ja paikallisista kansioista, holvinlaajuinen roskakori, tallennuspaikkojen kiintiöt ja tyhjennys, paikalliset vianjäljityslokit, alkuperäiset nimet, kansion turva (merkki, massapoiston esto, vain lähetys ja vain vastaanotto), ohitussäännöt, tiedostojen metatiedot, versiohistoria, QR-kutsut, reitittimen porttiohjaus, vähimmäisvapaa levytila, tapahtumavirta, vain luku -jäsenet, alustasäännöt, muutoshistoria ja jatkettavat siirrot kansiosta irrotettavien levyjen pinoon, yksi levy kerrallaan.

## Yhteensopivuus

Tallennusmuoto on ennallaan, mutta holvin jokaisen laitteen on oltava versiossa alpha.14: kirjanpidon näkymän välimuisti ja tietueiden tarkistukset muuttuivat, eivätkä vanhemmat laitteet lue sitä, mitä alpha.14 kirjoittaa. Päähaarassa oleva torrent-lataus ei kuulu tähän julkaisuun.
