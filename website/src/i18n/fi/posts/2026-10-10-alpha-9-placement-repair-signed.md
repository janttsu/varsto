---
title: Alpha.9: data sinne minne haluat sen, korjaus itsestään, allekirjoitetut päivitykset ja jokainen alusta käännettynä avoimesti
date: 2026-10-10
summary: Kansiot voi sijoittaa valittuihin tallennuspaikkoihin ja siirtää niiden välillä, kadonneet kopiot korjataan automaattisesti, päivitykset allekirjoitetaan avaimella joka ei poistu koneelta, vertaislataukset hakevat monta lohkoa kerralla, ja jokainen paketti käännetään, testataan ja kuvataan nyt GitHubin ajokoneilla.
---
Alpha.9 (käännös, jota ei koskaan merkitty omaksi julkaisukseen; sen muutokset tulivat version alpha.10 mukana) katsoo pitkälle: missä data asuu, miten se palaa niihin kopioihin, joita sääntösi pyytää, ilman erillistä käskyä, ja miten seuraavan version tuovaan päivitykseen voi luottaa.

## Data sinne, minne haluat sen

Jokaisella kansiolla voi nyt olla sijoittelu: tallennuspaikat, joihin sen lohkot menevät. Datan voi siirtää tallennuspaikasta toiseen (koko kansion, tai vain tiedostot jotka ovat olleet käyttämättä tietyn määrän päiviä), lohko kerrallaan. Kukin lohko kirjoitetaan ja luetaan takaisin uudella tallennuspaikalla ennen kuin vanha kopio poistetaan, ja keskeytynyt siirto jatkuu, kun sen ajaa uudelleen. Irrotettavien levyjen varasto voi pyytää kopioita levyille, joita pidetään eri paikoissa, esimerkiksi yksi kotona ja yksi töissä, ja Varsto täyttää kunkin levyn sillä, mitä sen paikasta vielä puuttuu.

## Korjaus itsestään

Kun kopio katoaa, tallennuspaikka poistetaan tai tarkistus epäonnistuu, dataa hallussaan pitävä laite laittaa lohkon takaisin sinne, minne kansion sääntö ja sijoittelu sen haluavat: omista tiedostoistaan, salattujen lohkojen välimuistista, toisesta tallennuspaikasta tai vertaiselta. Korjausjono näkyy käyttöliittymässä ja komennolla `varsto repair`.

## Allekirjoitetut päivitykset

Jokaisen julkaisun tarkistussummaluettelo allekirjoitetaan nyt projektin julkaisuavaimella, joka ei koskaan poistu ylläpitäjän koneelta, ja päivitysohjelma hylkää julkaisun, jota ei ole allekirjoitettu sillä. Se vertaa tarkistussummaa myös siihen, joka on liitetty GitHub-julkaisuun: toinen kanava. `varsto verify-release` tarkistaa latauksen käsin, ja niin tekee `minisign`. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) selittää järjestelyn.

## Nopeampi vertaisyhteys

Latauksissa on kerrallaan liikkeellä enintään kahdeksan lohkoa (silloin), pienet tiedostot haetaan ennakkoon kansion poikki ja vertaista kohden käytetään yhtä yhteyttä; lohkoja tarjoileva laite ei enää aloita omaa täyttä synkronointiaan muutaman sekunnin välein. [Suorituskykymittaukset](../benchmarks/) vertaavat Pariisia, Amsterdamia ja Varsovaa, vertaisyhteyttä S3-ämpäriä vastaan.

## Käännetty avoimesti

Jokainen alusta käännetään ja testataan nyt GitHubin ajokoneilla jokaisesta muutoksesta: Linux- ja Windows-paketit (Windows-paketti testattuna Windows Server 2025:llä, myös Explorerin valikkokohdat), Android-sovellus emulaattorissa, macOS-levykuva ja iOS-sovellus Apple Siliconilla. Samat ajot ottavat [kuvakaappaukset](../screenshots/), joten tämän sivuston kuvat seuraavat uusinta käännöstä.

## Ja lisää

Jako kirjaa sormenjäljellä, kuka pyysi käyttöoikeutta, jäsenen poistaminen siirtää jaon uusiin avaimiin, ja Strongroomin avaimen voi vaihtaa; tiedostoja voi ladata tai vapauttaa tiedostonhallinnasta Linuxissa (Nautilus, Dolphin, Nemo) ja Windowsissa (Explorer); kansiorivit pitävät kaksi pääpainikettaan ja panevat loput valikkoon; macOS-sovellus ja puhelinsovellukset sanovat, kun uudempi versio odottaa lataussivulla, sen sijaan että sanoisivat olevansa ajan tasalla; ja suuret kirjanpidon erät eivät enää epäonnistu S3:ssa.

## Päivitä jokainen laite ennen datan siirtoa

Datan siirtäminen kirjoittaa uudenlaisen kirjanpitomerkinnän, jota alpha.8 ja sitä vanhemmat eivät osaa lukea: niiden synkronoinnit epäonnistuisivat ensimmäisestä siirrosta alkaen. Päivitä ensin kaikki laitteesi. Tästä versiosta alkaen tuntemattomat merkinnät ohitetaan, joten myöhemmät lisäykset eivät riko sitä. Versioon alpha.8 asti asiakasohjelmat tarkistavat päivityksessä vain tarkistussumman; tämä julkaisu on ensimmäinen, jonka päivitysohjelma vaatii allekirjoituksen.

## Yhä alfa

Salausta ei ole auditoitu, muoto voi vielä muuttua, ja virhe voi hävittää dataa. Käytä testidataa ja pidä omat varmuuskopiosi.
