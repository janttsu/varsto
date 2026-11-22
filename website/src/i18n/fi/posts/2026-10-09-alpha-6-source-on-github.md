---
title: Alpha.6: lähdekoodi on julkinen, ja jokainen alusta käännetään pilvessä
date: 2026-10-09
summary: Tietovarasto on nyt julkinen GitHubissa PolyForm Shield -lisenssillä, natiivit macOS- ja iOS-sovellukset käännetään GitHub Actionsissa, Linux, Windows ja Android käännetään lyhytikäisillä pilvikoneilla, ja käyttöliittymä tehtiin uudelleen tiedostonäkymän ympärille.
---
Alpha-0:sta lähtien alfat ovat lisänneet suurimman osan siitä, mitä suunnitelma kutsuu ytimeksi: S3- ja rclone-tallennuspaikat, jakaminen toiselle ihmiselle sinetöidyllä avaimella, jälkikvanttiset hybridiallekirjoitukset ja avaimenvaihto, säilytyssäännöt jotka varoittavat ajoissa, vertaissiirto omien laitteidesi välillä, pakkaus ennen salausta, Strongroom-kansiot FIDO2-suojausavaimen takana, tulostettava palautuspaketti ja MCP-palvelin, jotta avustaja voi lukea ja järjestellä täsmälleen ne kansiot, joihin annat sille oikeuden. Alpha.6 koskee projektia tuon koodin ympärillä.

## Lähdekoodi on julkinen

Tietovarasto on osoitteessa [github.com/janttsu/varsto](https://github.com/janttsu/varsto) [PolyForm Shield License 1.0.0](../docs/licence.html) -lisenssillä: lähdekoodi on saatavilla, se ei ole avointa lähdekoodia. Lue se, käännä se, kerro ongelmaseurannassa mikä hajoaa. Historia kirjoitettiin uudelleen ennen julkaisua, jotta siinä ei ole henkilökohtaisia polkuja eikä osoitteita; jos kloonasit aiemman yksityisen kopion, kloonaa uudelleen.

## Jokainen alusta käännetään koneella, jota ei ollut tuntia aiemmin

- **macOS ja iOS** käännetään GitHub Actionsissa Apple Silicon -ajokoneilla: testisarja, natiivi Varsto.app omalla ikkunallaan, valikkorivin kohteellaan ja mukana tulevalla komentorivillä, sekä iOS-kuori Simulatorille, joka käynnistetään siellä ja kuvataan. Merkitty julkaisu saa macOS-zipin liitteeksi automaattisesti.
- **Linux, Windows ja Android** käännetään ja testataan lyhytikäisillä pilvikoneilla, jotka skripti luo, käyttää kerran ja poistaa: koko testisarja oikealla Ubuntulla, Windows-zip asennettuna ja ajettuna oikealla Windows Serverillä, Android-APK käännettynä SDK:lla ja NDK:lla ja sitten ajettuna emulaattorissa.

Yksikään käännös ei enää riipu kehittäjän kannettavasta. Siksi myös jokainen lataussivun paketti tulee dokumentoidusta, toistettavasta polusta.

## Tiedostonäkymä ensin

Käyttöliittymä tehtiin uudelleen: sivupalkki, jossa on kansiopuu, Tiedostot-näkymä murupolulla, tilaruuduilla ja tietoruudulla, sekä puhelintila, jossa taulukoista tulee kortteja ja navigointi siirtyy alareunaan. Puhelimessa kansio lisätään pelkällä nimellä; laite valitsee, missä se sijaitsee, joten hakemistoa ei tarvitse koskaan kirjoittaa. Asetuksissa on alfalle myös vahvistusta vaativa ”Aloita alusta tällä laitteella”, ja yleiskatsaus ehdottaa, missä käyttämättömät tiedostot olisi halvempi säilyttää, Varston omasta viimeksi käytetty -tiedosta ja avoimesta hintadatasta.

## Yhä alfa

Mikään tässä ei muuta varoitusta, joka on jokaisella sivulla: salausta ei ole auditoitu, muoto voi vielä muuttua, ja virhe voi hävittää dataa. Käytä testidataa, pidä omat varmuuskopiosi ja lue [vikamalli](../docs/failure-model.html), ennen kuin luotat siihen missään muussa.
