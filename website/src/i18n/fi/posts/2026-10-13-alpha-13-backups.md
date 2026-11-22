---
title: Alpha.13: varmuuskopiot, joita mikään ei voi muuttaa
date: 2026-10-13
summary: Valitse kansio millä tahansa laitteella, niin Varsto säilyttää siitä salattuja, vain luku -muotoisia tilannevedoksia ulkoisissa tallennuspaikoissasi, ei koskaan laitteillasi, niin monen päivän ajan kuin valitset (oletuksena 90). Palautukset menevät nimeämääsi hakemistoon, sovelluksesta tai komentoriviltä.
---
Synkronointi pitää jokaisen kopion samana, mikä on juuri sitä, mitä et halua, kun tiedosto poistetaan vahingossa tai kiristyshaittaohjelma salaa sen: vahinko yltää jokaiseen laitteeseen. Alpha.13 lisää varmuuskopiot, jotka toimivat toisin päin.

## Miten se toimii

Valitset kansion yhdellä laitteella ja annat varmuuskopiolle nimen. Varsto ottaa siitä tilannevedoksen: tiedostoluettelon ja jokaisen lohkon, salattuina kuten kaikki muukin, mitä se tallentaa. Tilannevedokset menevät vain ulkoisiin tallennuspaikkoihin (S3-ämpärit, rclone-etäkohteet, NAS-jaot, hakemistot ja kylmätallennus), ei koskaan siirtolevyille eikä muille laitteillesi. Muut laitteesi näkevät, että varmuuskopio on olemassa ja mitkä tilannevedokset sillä on, mutta ne eivät lataa sen sisältöä.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Tilannevedokset otetaan oletuksena päivittäin, viikoittain tai vain kun pyydät (`varsto backup take`). Lohkot, jotka eivät muuttuneet, tallennetaan kerran, käyttivät niitä miten monta tilannevedosta tahansa.

## Vain luku, ja säilytys määräajan

Tilannevedosta ei koskaan muokata sen ottamisen jälkeen. Sen vanhenemispäivä sinetöidään sen sisään, kun se kirjoitetaan, joten säilytysajan muuttaminen myöhemmin vaikuttaa vain uusiin tilannevedoksiin. Kun tilannevedos on vanhentunut, varmuuskopion tehnyt laite poistaa sen tallennuspaikoista. Vain ne lohkot poistetaan, joita mikään jäljellä oleva tilannevedos ei tarvitse, ja yhden päivän armonaika antaa tilaa kelloille, jotka ovat hieman väärässä. Jos se laite on poissa, holvin mikä tahansa muu laite tekee sen vähän myöhemmin. Varmuuskopion pysäyttäminen ei ota uusia tilannevedoksia, mutta ei poista mitään etuajassa.

## Palauttaminen

Palautus menee aina hakemistoon, jonka nimeät, ja sen hakemiston on oltava tyhjä, ellet salli päällekirjoitusta. Voit valita uusimman tilannevedoksen, numeroidun tai uusimman, joka on tiettynä päivänä tai sitä ennen, ja palauttaa kaiken tai vain joitakin polkuja. Sovelluksessa on Varmuuskopiot-sivu, joka tekee saman.

## Yksityiskohdat ja rajat

Muoto on [määrittelyn](../docs/alpha-0-format.html) kohdassa 31. Tässä ensimmäisessä versiossa vanheneminen seuraa kunkin laitteen omaa kelloa, säilytyssäännöt eivät vielä kata varmuuskopioita, eikä näkymä siitä missä data on näytä niitä.

Vanhemmat versiot eivät ymmärrä varmuuskopioita: päivitä holvin jokainen laite versioon alpha.13 ennen kuin lisäät sellaisen.
