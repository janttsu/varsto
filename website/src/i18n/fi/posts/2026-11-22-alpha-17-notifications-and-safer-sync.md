---
title: Alpha.17: holvi pysyy, hiljaiset virheet lähtevät
date: 2026-11-22
summary: Ei uutta tallennusmuotoa eikä uusia sanoja kirjoitettavaksi. Alpha.17 on julkaisu, joka estää epäonnistunutta synkronointia poistamasta tiedostoja, säilyttää viimeisen varmuuskopion ja kertoo puhelimeesi, kun jokin on oikeasti vialla.
---
Tämän voit päivittää ilman seremoniaa. Alpha.17 avaa alpha.16:n holvin sellaisenaan. Uutta muotoa ei ole, ei toista sanajoukkoa, eikä mitään, mikä pitäisi luoda uudelleen. Mikä muuttuu, on sellainen virhe, joka ennen sattui sillä aikaa, kun katsoit muualle.

Haku, joka ei koskaan valmistunut, saattoi silti julkaista poistetuiksi tiedostoja, joita tämä laite ei ollut lukenut. Varmuuskopion uusin tilannevedos saattoi vanhentua ja viedä mukanaan ainoan kopion, josta voi palauttaa. Ensimmäinen kohtaaminen toisen laitteen kanssa saattoi seistä paikallaan vartin ja näyttää kuolleelta. Juuri niitä varten tämä julkaisu on. Se on yhä alfa, eikä se ole sellaista dataa varten, jota sinulla ei ole varaa menettää. Pitkä lista on muutoslokissa. Osat, jotka oikeasti huomaat, ovat alla.

## Puhelimesi kuulee siitä

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="Kannettava lähettää puhelimeen hälytyksen siitä, että Documents-kansiossa tila on loppumassa. Itse holvi pysyy tietokoneella." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="Kannettava lähettää puhelimeen hälytyksen siitä, että Documents-kansiossa tila on loppumassa. Itse holvi pysyy tietokoneella." width="640" height="320"></picture>
</figure>

Laite voi nyt kertoa puhelimeesi ntfy:n, Pushoverin tai Telegramin kautta, kun jokin tarvitsee ihmisen. Lisää kanava Asetuksissa tai komennolla `varsto notify`. Jokaisella palvelulla on lyhyt opas ja testiviesti, ja sinä valitset, mitä sen saa sanoa. Kansioiden, tallennuspaikkojen ja laitteiden nimet voivat jäädä tekstistä pois.

Merkittävät hälytykset ovat päällä, ellet sammuta niitä: tallennuspaikka pulassa, levy jolta tila loppuu, vähemmän kopioita kuin sääntö pyytää, vahingoittunut data, varmuuskopio joka epäonnistui tai on myöhässä, pyyntö joka odottaa sinua. Valmiit varmuuskopiot, uudet tiedostot ja päiväyhteenveto pysyvät hiljaa, kunnes pyydät niitä. Tunnukset ovat laitteella, tiedostossa `notify.json`, eikä niitä synkronoida. Itse viesti ei ole päästä päähän salattu matkallaan ntfy:n, Pushoverin tai Telegramin läpi. Se kannattaa tietää, ennen kuin annat sen nimetä kansion. Epäonnistunut lähetys jää odottamaan ja sitä yritetään uudelleen, myös uudelleenkäynnistyksen jälkeen. Samaa hälytystä ei toisteta kuuteen tuntiin, ja kanava saa enintään kaksikymmentä viestiä tunnissa. Tämän voi tehdä, kun holvi on lukossa.

## Haku, jolla tavut jo ovat

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Salatekstillohkot pysyvät kannettavalla. Yksi yhteys vie lukittuun pilveen vain puuttuvat lohkot." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Salatekstillohkot pysyvät kannettavalla. Yksi yhteys vie lukittuun pilveen vain puuttuvat lohkot." width="640" height="320"></picture>
</figure>

Suurin osa muuttuneesta tiedostosta oli jo täällä. Alpha.17 lakkaa hakemasta niitä lohkoja uudelleen. Muuttuneen tiedoston muuttumattomat osat tulevat levyllä olevasta edellisestä versiosta. Uudelleennimetty tai siirretty tulee vanhasta polusta, tai roskakorista, jos se meni sinne. Saman tiedoston kaksi kopiota hakee kunkin erilaisen lohkon kerran. Paikallisesti luettu tarkistetaan palansa tunnistetta vasten, ja lohko joka ei täsmää haetaan sittenkin.

Toinen puoli on laite, joka juuri kirjoitti tiedoston. Se tarjoaa jokaisen paikalleen laittamansa tiedoston muille heti, ei vasta kun sen oma synkronointi on päättynyt, ja pyynnöt jaetaan niiden vertaisten kesken, joilla lohkot oikeasti ovat.

Kun tämä laite tapaa toisen ensimmäisen kerran, ennen kuin tuo laite on lukenut tämän varmenteen, polku näytetään yhdistämisenä ja sitä yritetään heti uudelleen. Myöhempi kieltäytyminen odottaa muutaman sekunnin ja näytetään tavoittamattomana. Laite, joka ei ole koskaan vastannut, ei enää käytä minuuttia ja sitten jopa viittätoista ennen ensimmäistä oikeaa yritystä. Kun ensimmäinen synkronointi on yhä kesken, kansio jossa ei ole vielä tiedostoja näytetään haettavana. Se ei ole tyhjä kansio, joka olisi jo valmis.

Vertainen, joka vastasi ja sitten pettää, lepää sekunnin, ja lepo kaksinkertaistuu, tasaisen minuutin sijaan. Lohkoa, jota kellään muulla ei ole, kysytään siltä vertaiselta vielä kerran. Jos vertainen käynnistyy uudelleen, seuraava synkronointi, uudempi vertaistietue tai lähiverkon majakka lopettaa levon, eikä jokaista tiedostoa ilmoiteta puuttuvaksi. Laitteet, jotka ovat vain poissa, lepäävät kauemmin, ja niistä kysytään jopa kahdeksaa kerralla, joten ne maksavat yhden aikakatkaisun eikä kahdeksaa.

## Mitä epäonnistuminen ei enää saa tehdä

Epäonnistunut haku ei enää julkaise poistetuiksi tiedostoja, joita tämä laite ei ole lukenut. Sen, minkä lisäsit tai muokkasit täällä, tämä laite yhä lähettää. Seuraava haku hakee kopiot, jotka muilla laitteilla yhä on, ennen kuin puuttuva tiedosto voidaan todeta menneeksi.

Jos toisen laitteen versio voittaa ristiriidan, täällä oleva tiedosto väistyy vasta kun voittaja on oikeasti perillä. Voittaja, jota ei saatu haettua, jätti ennen polun tyhjäksi, ja seuraava työntö julkaisi sitten sen poiston. Tiedosto, joka kasvaa tai pienenee skannauksen lukiessa sitä, odottaa seuraavaa skannausta. Sitä ei julkaista koolla, jota sen lohkot eivät kanna. Ennen se sai jokaisen muun laitteen hylkäämään kansion koko luettelon.

Paketit, joita kukaan ei ole väittänyt, poistetaan 48 tunnin kuluttua, tai 24 tunnin kuluttua kun paikallisella tallennuspaikalla on vapaana alle 10 prosenttia. Ennen se oli seitsemän päivää. Työntö, tuonti tai varmuuskopio, jonka karttatietue ei koskaan tullut julkaistuksi, poistaa juuri kirjoittamansa paketit. Samoin tekee korjaus, jonka erää ei sinetöity. Jos sinetöinti epäonnistuu sen jälkeen kun karttatietue on julkaistu, paketit jäävät, koska väite on jo kirjanpidossa. `varsto gc orphans` poistaa ne nyt, jos et halua odottaa.

Varmuuskopion säilytys ei enää syö uusinta tilannevedosta vain siksi, että se on vanha. Kadonnut lähdehakemisto, tai laite joka ei koskaan ottanut uudempaa, vanhensi ennen tuon tilannevedoksen aikataulun mukaan ja keräsi sitten sen lohkot, eikä jäljelle jäänyt mitään palautettavaa. Varmuuskopion pysäyttäminen antaa yhä viimeisen tilannevedoksen vanhentua. Se osa ei muutu, ja niin sanot, että olet sen kanssa valmis.

## Kellot, nimet ja avain, joka eli laitetta kauemmin

Kaksi prosessia samalla koneella, komentorivi ja taustapalvelu, eivät voi enää varata samaa Lamport-arvoa ja sitten molemmat jakaa sitä eteenpäin. Varaus pitää lukkoa koko ajan, kun arvo luetaan, nostetaan ja kirjoitetaan takaisin.

Kaksi laitetta, jotka kirjoittavat saman holvin tai kansion kausinumeron, eivät enää lopeta allekirjoittamista, kunnes joku valitsee. Laite, joka näkee molemmat tietueet, pitää sen, jonka myöntäjän tunniste on suurempi. `varsto device resolve-epoch` ja `varsto folder resolve-epoch` korvaavat yhä tuon valinnan, kun haluat toisen.

Levyllä, joka ei erota kirjainkokoja, kaksi polkua jotka eroavat vain kirjainkoon tai Unicoden normalisoinnin osalta saavat eri paikalliset nimet sen mukaan, kumpi ehtii ensin. Tasatilanteessa voittaa NFC-kirjoitusasu. Sitten pienempi alkuperäinen polku pitää pelkän nimen, ja toisesta tulee ` (2)`.

Laitteen poistaminen ei itsessään vaihda salasanaa tallennuspalvelun tarjoajalla. Nyt se kieltäytyy unohtamasta. `varsto status` ja `varsto device list` nimeävät jokaisen tallennuspaikan, jonka tunnuksilla se laite voisi yhä poistaa salatekstiä. Kun olet vaihtanut ne palveluntarjoajalla, `varsto storage mark-rotated <name>` poistaa varoituksen. Varsto ei vaihda salaisuutta puolestasi.

## Paperilla olevat sanat ja avaimet, jotka ennen olivat tiedostossa

`varsto recovery kit` tulostaa muodon 3 paketin: holvisanat ja palautussanat. Ennen se tulosti muodon 2 tekstin, joka sanoi että 24 holvisanaa lukevat kaiken holvissa. Muodossa 3 ne avaavat laitteiden nimet, kansioiden nimet ja tallennuksen kirjanpidon. Sisältö tarvitsee palautussanat. Tuloste, joka on tehty ilman niitä, sanoo sen nyt suuraakkosin, eikä näytä enää valmiilta. `--shares` jakaa molemmat joukot.

Jakopyyntö ja organisaatiopyyntö pitivät ennen yksityiset avaimensa selväkielisessä JSON-tiedostossa. Laitteen hakemistosta otettu kopio, pyynnön vielä odottaessa, saattoi lukea ne, ja kun omistaja oli hyväksynyt pyynnön, avata kansion ilman mitään salalausetta. Avaimet sinetöidään nyt laitteen salalauseen alle. Pyyntökoodin näyttäminen kysyy sitä, ja pyynnön hyväksyminen kysyy uudelleen. Pyyntö, jonka alpha.16 jätti selväkieliseksi, sinetöidään seuraavalla kerralla kun komento lukee sen.

Lokit saavat saman kohtelun sille, miten vianetsinnän tuloste kirjoittaa valinnaisen arvon. Rivi kuten `password: Some("…")` katkaistiin lainausmerkin kohdalta, ja salaisuus jäi rivin loppuun. Salalause rekisteröidään puhdistimeen jokaisella avausreitillä, myös kun palvelu palaa avainnipusta. Ennen tuo palvelu saattoi olla käynnissä päiväkausia ilman että mitään oli rekisteröity.

## Tauko, joka tarkoittaa taukoa

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="Keskeytetty puhelin kodin kannettavan ja toimiston NASin välissä. Molemmat yhteydet on merkitty pois." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="Keskeytetty puhelin kodin kannettavan ja toimiston NASin välissä. Molemmat yhteydet on merkitty pois." width="640" height="320"></picture>
</figure>

Taustapalvelun keskeytys pysäytti ennen synkronoinnin ja jätti laitteen muun osan puheliaaksi. Kuuntelija, lähiverkon majakka, kohtaamispalvelu, välitys ja reitittimen porttikartoitus pysähtyvät nyt sen mukana, ja ne pysyvät pysähdyksissä kunnes jatkat. Itse asettamasi keskeytys säilyy uudelleenkäynnistyksen yli. Sillä on väliä puhelimessa, joka pysäyttää ja käynnistää palvelun pitkin päivää. Lyhyttä taukoa, jonka `varsto disk` tai tuonti ottaa omaksi tarpeekseen, ei tallenneta. Se päättyy komennon päättyessä.

Esikatselukuvat tiedostoluettelossa näkyvät puhelimissa taas. Kun moottori oli kiireinen, palvelu vastasi ennen ettei esikatselukuvaa ole, ja sivu uskoi. Nyt se vastaa että on kiireinen, ja sivu yrittää uudelleen.

Oletussääntö ei enää merkitse kansiota rikotuksi holvissa, jossa ei ole levyvarastoa eikä hakemistotallennuspaikkaa. Varoitus on yksi: mikään ei ole omalla levylläsi, ja miten sellaisen lisäät. Sääntö, jonka asetit itse ja joka oikeasti vaatii kopion kotona, pidetään yhä voimassa. Sama ero pätee, kun tuonti päättää saako sen lähteen poistaa, joten sellaisen holvin kansio ei enää odota ikuisesti kopiota levyltä, jota sinulla ei ole.

Komento ja taustapalvelu ottavat saman lukon, kun tiedostoa haetaan, vapautetaan, kirjoitetaan tai siirretään, joten ne eivät enää kumoa toistensa kansion tilaa. Epäonnistunut lataus tai kirjoitus ei enää jätä tiedostoa `.varsto-tmp-…` tai `.varsto-upload-…` pitämään osaa sisällöstä. Toiselta laitteelta tulevat tiedostot säilyttävät muokkausajan, jonka kirjoittaja kirjasi, eikä niihin leimata lataushetkeä. Työkalut, jotka luottavat päivämäärään, koonti, kuvakirjasto, toinen varmuuskopio, eivät enää näe jokaista haettua tiedostoa uutena.

## Poistettu laite pysyy poistettuna

Poistetun laitteen kansiotietueet, myönnöt ja palautusvaraus lasketaan vain siihen ensimmäiseen järjestysnumeroon saakka, jonka se jätti tyhjäksi. Se ei voi myöhemmin palata ja täyttää aukkoa jälkikäteen tehdyllä tietueella. Toisen holvin jäsen ottaa käyttöön poiston, jonka se lukee kansion kaudesta. Kansio, jota poistaja ei voinut avaintaa uudelleen, avainnetaan uudelleen seuraavassa synkronoinnissa omistajalla, jolla avain yhä on. Sen, mitä poistetulla laitteella jo on omalla levyllään, se saa pitää. Näin oli aina, ja näin on yhä.

Liittyminen lukee organisaation manifestin ja ottaa holvin kaudet ja kumoukset vain sen ylläpitäjiltä. Jäsenluettelon tavallisen jäsenen kirjoittama kumous ei enää avaa holvia laitteelle, joka on liittymässä.

Toimintalokin rivillä ”ei avainta” on sama painike kuin kansion rivillä, joten puhelin voi pyytää käyttöoikeutta siltä riviltä eikä kansiota tarvitse etsiä. Restic-peili ja sen alle liitetyt kansiot luodaan niin, että vain tämä käyttäjä voi lukea ne.

## Nimi kuvakkeessa

Sovellustunnukset ovat nyt `net.varsto.app` Androidilla ja macOS:llä, `net.varsto.app.ios` iOS:llä ja `net.varsto.app.alpha` allekirjoittamattomalle macOS-käännökselle. Jo asennettu sovellus säilyttää entisen tunnuksensa, eikä sen holvia siirretä, ennen kuin asennat sen uudelleen. Uuden paketin asentaminen vanhan viereen ei korvaa sitä.

## Jos olet versiossa alpha.16

Päivitä milloin haluat. Versiot voivat jakaa holvin sillä välin. Mikään tässä julkaisussa ei käske sinua nollaamaan, tulostamaan uutta pakettia tai poistamaan Android-käännöstä, joka on jo alpha.16:n julkaisuallekirjoitettu. Jos jakopyyntö tai organisaatiopyyntö odottaa yhä selväkielisessä tiedostossa alpha.16:sta, seuraava komento joka lukee sen sinetöi sen. Tämä on yhä alfa.
