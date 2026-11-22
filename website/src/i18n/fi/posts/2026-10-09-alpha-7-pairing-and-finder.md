---
title: Alpha.7: parita laitteet koodilla, Finder-toiminnot ja oikea NAT-reitti
date: 2026-10-09
summary: Laitteet pariutuvat nyt käyttöliittymästä kertakäyttöisellä koodilla, Finder voi ladata paikkamerkin tai vapauttaa tilaa hiiren oikealla painikkeella, macOS-sovellus asentuu levykuvasta, laitteet tavoittavat toisensa NATin läpi, ja irrotettavista levyistä voi tehdä varaston.
---
Alpha.7 on enimmäkseen tulosta siitä, että alfaa käytettiin oikeilla laitteilla yhden päivän: Samsung-puhelimella, Macilla ja testiämpärillä. Jokainen alla oleva osio alkoi siitä, että jokin ei toiminut niin kuin sen piti.

## Parita laite koodilla

Laitteen lisääminen tarkoitti ennen 64 merkin holviavaimen kopioimista ja sellaisen tallennuspaikan asetusten kirjoittamista, johon molemmat laitteet yltävät. Nyt laite, jolla holvi jo on, näyttää Laitteet-kohdassa **Lisää laite**: yhdeksän numeron koodi, joka toimii kerran, kymmenen minuuttia. Uudella laitteella valitset **Muodosta pari toisen laitteesi kanssa**, kirjoitat koodin, nimen ja salalauseen. Siinä kaikki.

Laitteet löytävät toisensa lähiverkosta ja ajavat SPAKE2:n, joka on avainnettu koodilla (väärää arvausta ei voi tarkistaa ilman yhteyttä, ja kolme väärää koodia sulkee tarjouksen), vahvistavat avaimen molempiin suuntiin, ja vasta sitten holviavain kulkee, mukanaan tallennuspaikkojen asetukset ja niiden salaisuudet, sinetöitynä yhteisen avaimen alle. Uusi laite liittyy ensimmäisen tallennuspaikan kautta, johon se yltää. Jos sitä ei löydy verkosta, koodin alla näkyvä osoite toimii myös. Sama kulku on komentorivillä: `varsto pair offer` ja `varsto pair join`.

## Finder tuntee paikkamerkit

macOS:ssä tiedostoja voi napsauttaa hiiren oikealla ja valita **Lataa Varstolla** tai **Vapauta tilaa Varstolla**, ja paikkamerkin kaksoisnapsautus lataa tiedoston ja avaa sen. Tilaa ei vapauteta, ellei jokainen lohko ole tallennuspaikassa *ja* levyllä oleva tiedosto ole se versio, joka synkronoitiin; ennen tätä julkaisua tiedosto, jota oli muokattu viimeisen synkronoinnin jälkeen, olisi voitu korvata paikkamerkillään. macOS-lataus on nyt levykuva: avaa se ja vedä Varsto Applications-kansioon.

## Laitteet tavoittavat toisensa NATin läpi

Vertaissiirto toimi ennen lähiverkossa ja edelleenohjattujen porttien kautta. Nyt laitteet saavat julkisen osoitteensa STUNilla, puhkaisevat NATin QUICin yli varmenteella, joka on kiinnitetty laitekohtaisesti, ja turvautuvat tarvittaessa välitykseen jonkin oman tavoitettavan laitteesi kautta. Sitä kokeiltiin kotiverkon ja oman NATinsa takana olevan pilvikoneen välillä, molempiin suuntiin, ja UDP estettynä niin että välitys oli ainoa tie.

## Irrotettavien levyjen varastot

Tallennuspaikka voi olla irrotettavien levyjen varasto: Varsto täyttää ne vapaan tilan mukaan ja jättää varauksen, tietää mikä levy pitää minkäkin lohkon, pyytää sinua liittämään tietyn levyn, kun se tarvitsee sitä, ja laskee offline-levyn kopioksi sellaisena kuin se oli viimeisessä tarkistuksessa.

## Pienempiä asioita

- Säilytyssääntöjä muokataan työpöydällä jokaiselle kansiolle samassa taulukossa, ja koko sääntö perusteluineen näkyy.
- Puhelimessa voit lisätä tiedostoja ja alikansioita, avata tiedoston toisessa sovelluksessa tai jakaa sen, ja pitää kansion selväkielisinä tiedostoina sisäisessä tallennustilassa salatun sijaan.
- Tiedoston tiedoissa sanotaan, onko tiedosto tällä laitteella ja mitkä tallennuspaikat pitävät sitä.
- Ikkuna seuraa taukoa tai synkronointia, joka aloitetaan valikkoriviltä.
- Liittyminen hyväksyy 24 palautussanaa samoin kuin heksadesimaaliavaimen.

## Yhä alfa

Jokaisella sivulla oleva varoitus pätee: salausta ei ole auditoitu, muoto voi vielä muuttua, ja virhe voi hävittää dataa. Käytä testidataa ja pidä omat varmuuskopiosi.
