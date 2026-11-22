---
title: Alpha.8: kirjanpito joka pysyy pienenä, irrotettavat laitteet ja puhelimet, jotka eivät säilytä mitään selväkielisenä
date: 2026-10-09
summary: Kirjanpito listaa nyt vain sen, mikä on uutta, pitää välimuistissa olevan näkymän ja karsii itseään allekirjoitettujen tarkistuspisteiden takaa; laitteen voi poistaa, ja sen jälkeen kirjoitettu saa uudet avaimet; puhelimet pitävät salatut kansiot salattuina lohkoina; ja käyttöliittymä näyttää, missä datasi on ja miten vertaisliikenne kulkee.
---
Alpha.8 syntyi pitkästä päivästä, jona alpha.7:ää käytettiin Macilla, Linux-työpöydällä ja Samsung-puhelimella, ja siitä kysymyksestä, mitä suunnitelmalle tapahtuu muutaman käyttövuoden jälkeen.

## Kirjanpito, joka pysyy pienenä

Jokainen laite pitää allekirjoitettua, salattua lokia tosiasioista: minkä lohkon se tallensi minne, minkä kopion se tarkisti, minkä tiedostoluettelon se julkaisi. Tähän asti jokainen merkintä jäi ikuisiksi ajoiksi omaksi objektikseen jokaiseen tallennuspaikkaan, ja jokainen synkronointi listasi ne kaikki. Nyt synkronointi listaa vain sen, mikä on uutta, laite pitää välimuistissa salattua näkymää kaiken toistamisen sijaan, yksi synkronointi kirjoittaa yhden erän, ja jokainen laite kirjoittaa ajoittain allekirjoitetun tarkistuspisteen. Kun kaikki laitteesi ovat kuitanneet tarkistuspisteen, sen takana olevat erät poistetaan, mutta viimeiset jätetään, jotta vanhasta varmuuskopiosta palautettu laite saadaan yhä kiinni. Testiholvissa, jossa oli 20 000 erää, synkronointi jossa ei ollut mitään uutta vei 668 ms:n sijaan 28 ms (silloin), ja kirjanpito tallennuspaikassa 171 MB:n sijaan 5 MB. [Miten se toimii](../how-it-works/) -sivu selittää kirjanpidon.

## Laitteen poistaminen

Kadonnut puhelin tai kannettava, jota et enää käytä, voidaan poistaa miltä tahansa muulta laitteelta (Asetukset tai Vertaiset, ”Poista…”, tai `varsto device revoke`). Sen myöhemmät merkinnät jätetään huomiotta, laitteesi torjuvat sen yhteydet, ja holvi siirtyy uusiin avaimiin, jotka vain jäljelle jäävät laitteesi saavat, joten mikään sen jälkeen kirjoitettu ei aukea sillä, mitä poistetulla laitteella on. Voit myös käskeä sen tyhjentämään itsensä seuraavalla kerralla, kun se tavoittaa tallennuspaikan. Laiteluettelo näyttää kunkin laitteen järjestelmän, mallin, Varsto-version ja viimeisimmän synkronoinnin.

## Puhelimet pitävät salatut kansiot salattuina

Kansio, joka pidetään ”salattuna tällä puhelimella”, sisältää nyt vain salattuja lohkoja, samoja tavuja kuin tallennuspaikkasi. Valikoiva synkronointi toimii kuten muuallakin; tiedostot näytetään sovelluksen omassa katseluohjelmassa, puretaan muistissa ja annetaan toiselle sovellukselle vain kun pyydät, väliaikaisena kopiona, joka poistetaan kun holvi lukittuu. Android voi lähettää uudet kuvat ja videot valitsemaasi kansioon.

## Näet, mitä tapahtuu

- **Missä datasi on**: kaavio kansioista tallennuspaikkoihin ja laitteisiin, ja montako kopiota kaikella on.
- **Vertaisliikenne**: mikä laite lähettää mitä mille, mitä reittiä ja millä nopeudella.
- **Automaattinen tarkistus**: toinen laite lukee lohkosi uudelleen aikataulussa, joten sääntö kuten ”tarkistettu 30 päivän sisällä” toteutuu itsestään.
- Painikkeet näyttävät heti, että jokin alkoi, ja lataukset näyttävät edistymisensä.

## Ja lisää

Olemassa olevista kansioista voi tehdä Strongroom-kansioita, ja ne saavat vara-avaimen; tallennuspaikan voi poistaa, kun sen lohkot on kopioitu sinne missä niitä tarvitaan; kansion voi irrottaa tai poistaa holvista, ja ylimmän tason nimet ovat yksikäsitteisiä; siirtolevylle voi antaa kohdelaitteen; tallennuspaikkojen hinnoista lasketaan kustannusarviot, ja käyttämättömät tiedostot voi vapauttaa yhdellä napsautuksella; avustaja (MCP) ei voi koskaan poistaa tai korvata tiedostoja; ja Linuxissa ensimmäinen käynnistys asentaa Varston sinun käyttäjällesi, ja taustapalvelu jatkaa synkronointia myös niille, jotka käyttävät vain komentoriviä.

## Yhä alfa

Salausta ei ole auditoitu, muoto voi vielä muuttua, ja virhe voi hävittää dataa. Käytä testidataa ja pidä omat varmuuskopiosi.
