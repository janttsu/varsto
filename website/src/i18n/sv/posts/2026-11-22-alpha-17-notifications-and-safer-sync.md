---
title: Alpha.17: valvet blir kvar, de tysta misstagen försvinner
date: 2026-11-22
summary: Inget nytt lagringsformat och inga nya ord att skriva ner. Alpha.17 är versionen som hindrar en misslyckad synk från att radera filer, behåller den senaste säkerhetskopian och talar om för din telefon när något faktiskt är fel.
---
Den här kan du uppdatera utan någon ceremoni. Alpha.17 öppnar ett valv från alpha.16 som det är. Det finns inget nytt format, ingen andra uppsättning ord och inget att skapa på nytt. Det som ändras är den sortens misstag som brukade hända medan du tittade på något annat.

En hämtning som aldrig blev klar kunde ändå publicera raderingar av filer som den här enheten inte hade läst. Den nyaste versionen av en säkerhetskopia kunde bli för gammal och ta den enda återställningsbara kopian med sig. Det första mötet med en annan enhet kunde sitta där en kvart och se dött ut. Det är det den här versionen är till för. Det är fortfarande en alfa, och den är fortfarande inte för data du inte har råd att förlora. Den långa listan finns i ändringsloggen. Det du faktiskt kommer att märka står nedan.

## Din telefon får veta

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="En bärbar dator skickar en varning om lågt diskutrymme för mappen Dokument till en telefon. Själva valvet stannar på datorn." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="En bärbar dator skickar en varning om lågt diskutrymme för mappen Dokument till en telefon. Själva valvet stannar på datorn." width="640" height="320"></picture>
</figure>

En enhet kan nu tala om för din telefon, via ntfy, Pushover eller Telegram, när något kräver en person. Lägg till en kanal under Inställningar eller med `varsto notify`. Varje tjänst har en kort guide och ett testmeddelande, och du väljer vad den får säga. Namn på mappar, lagringsplatser och enheter kan hållas utanför texten.

De varningar som betyder något är på om du inte stänger av dem: en lagringsplats i trubbel, en disk som får slut på utrymme, färre kopior än en regel kräver, skadade data, en säkerhetskopia som misslyckades eller är försenad, en förfrågan som väntar på dig. Slutförda säkerhetskopior, nya filer och en daglig sammanfattning förblir tysta tills du ber om dem. Token finns på enheten, i `notify.json`, och synkas aldrig. Själva meddelandet är inte totalsträckskrypterat på vägen genom ntfy, Pushover eller Telegram, vilket är värt att veta innan du låter det namnge en mapp. En sändning som misslyckas väntar och prövas igen, också efter en omstart. Samma varning upprepas inte på sex timmar, och en kanal får högst tjugo meddelanden i timmen. Du kan ställa in det här medan valvet är låst.

## En hämtning som redan har bytena

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Blocken med chiffertext stannar på den bärbara datorn. En enda länk bär bara de block som saknas till ett låst moln." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Blocken med chiffertext stannar på den bärbara datorn. En enda länk bär bara de block som saknas till ett låst moln." width="640" height="320"></picture>
</figure>

Det mesta av en ändrad fil fanns redan här. Alpha.17 slutar hämta de blocken igen. De oförändrade delarna av en ändrad fil kommer från den föregående versionen på disken. Ett namnbyte eller en flytt kommer från den gamla sökvägen, eller från papperskorgen om det var dit den tog vägen. Två kopior av samma fil hämtar varje unikt block en gång. Allt som läses lokalt kontrolleras mot sitt bit-id, och ett block som inte stämmer hämtas ändå.

Den andra halvan är enheten som just skrev filen. Den serverar varje fil den har lagt på plats till de andra genast, inte först när dess egen synk har tagit slut, och förfrågningarna delas mellan de peers som faktiskt har blocken.

Första gången den här enheten möter en annan, innan den enheten har läst det här certifikatet, visas vägen som ”ansluter” och prövas igen genast. Ett senare avvisande väntar några sekunder och visas som ”kan inte nås”. En enhet som aldrig har svarat spenderar inte längre en minut, och sedan upp till femton, innan det första riktiga försöket. Medan den första synken fortfarande pågår visas en mapp som ännu inte har några filer som att den hämtas. Det är inte en tom mapp som redan är klar.

En peer som svarade och sedan misslyckas vilar en sekund, och vilan fördubblas, i stället för en fast minut. Ett block som ingen annan har frågas den peeren om en gång till. Om peeren startar om avslutar nästa synk, en nyare peer-post eller en fyr i det lokala nätverket vilan, i stället för att rapportera varje fil som otillgänglig. Enheter som helt enkelt är borta vilar längre, och upp till åtta av dem frågas tillsammans, så de kostar en timeout i stället för åtta.

## Vad ett misslyckande inte längre får göra

En hämtning som misslyckas publicerar inte längre raderingar av filer som den här enheten inte har läst. Det du har lagt till eller redigerat här sänds ändå. Nästa hämtning hämtar kopiorna som de andra enheterna fortfarande har innan en saknad fil kan förklaras borta.

Om en annan enhets version vinner en konflikt flyttas filen här undan först när vinnaren faktiskt har kommit fram. En vinnare som inte kunde hämtas lämnade förr sökvägen tom, och nästa sändning publicerade sedan en radering av den. En fil som växer eller krymper medan avläsningen läser den väntar på nästa avläsning. Den publiceras inte med en storlek som dess block inte rymmer, vilket förr fick varje annan enhet att vägra mappens hela lista.

Paket som ingen gjort anspråk på raderas efter 48 timmar, eller efter 24 när en lokal lagringsplats har under 10 procent ledigt. Det var sju dagar. En sändning, en import eller en säkerhetskopia vars kartpost aldrig blev publicerad raderar paketen den just skrev, och det gör också en reparation vars batch inte förseglades. Om förseglingen misslyckas efter att kartposten publicerats blir paketen kvar, eftersom påståendet redan finns i liggaren. `varsto gc orphans` raderar paket utan anspråk nu, om du hellre inte vill vänta.

Lagringstiden för en säkerhetskopia äter inte längre upp den nyaste versionen bara för att den är gammal. En förlorad källkatalog, eller en enhet som aldrig tog en nyare, brukade låta den versionen gå ut enligt schemat och sedan samla in dess block, och då fanns inget kvar att återställa. Att stoppa säkerhetskopian låter fortfarande den sista versionen gå ut. Den delen är oförändrad, och det är så du säger att du är klar med den.

## Klockor, namn och en nyckel som överlevde enheten

Två processer på en maskin, kommandoraden och bakgrundstjänsten, kan inte längre reservera samma Lamport-värde och sedan båda dela ut det. Reservationen håller ett lås över läsningen, höjningen och bytet.

Två enheter som skriver samma epoknummer för valv eller mapp slutar inte längre signera tills en person väljer. Enheten som ser båda posterna behåller den med det större utfärdar-id:t. `varsto device resolve-epoch` och `varsto folder resolve-epoch` ersätter fortfarande det valet när du vill ha ett annat.

På en disk som inte skiljer på skiftläge får två sökvägar som bara skiljer sig i skiftläge eller i Unicode-normalisering olika lokala namn, oavsett vilken som kommer först. NFC-stavningen vinner vid lika. Sedan behåller den mindre ursprungliga sökvägen det enkla namnet, och den andra blir ` (2)`.

Att ta bort en enhet ändrar inte, i sig, lösenordet hos lagringsleverantören. Det den gör nu är att vägra glömma. `varsto status` och `varsto device list` namnger varje lagringsplats vars uppgifter den enheten fortfarande kunde använda för att radera chiffertext. När du har bytt dem hos leverantören tar `varsto storage mark-rotated <name>` bort varningen. Varsto roterar inte hemligheten åt dig.

## Orden på papper, och nycklarna som brukade ligga i en fil

`varsto recovery kit` skriver ut återställningspaketet för format 3: valvorden och återställningsorden. Förr skrev det ut texten för format 2, som sa att de 24 valvorden läser allt i valvet. I format 3 öppnar de enhetsnamn, mappnamn och lagringsliggaren. Innehåll kräver återställningsorden. En utskrift som gjorts utan dem säger det nu med versaler, i stället för att se komplett ut. `--shares` delar båda uppsättningarna.

En delningsbegäran och en organisationsbegäran hade förr sina privata nycklar i en JSON-fil i klartext. En kopia av enhetskatalogen, tagen medan begäran väntade, kunde läsa dem, och när ägaren hade godkänt öppna mappen utan någon lösenfras alls. Nycklarna är nu förseglade under enhetens lösenfras. Att visa begärandekoden frågar efter den, och att godkänna begäran frågar igen. En begäran som alpha.16 lämnade i klartext förseglas nästa gång ett kommando läser den.

Loggarna får samma behandling för sättet en felsökningsskrivare skriver ett valfritt värde. En rad som `password: Some("…")` klipptes förr vid citattecknet och lämnade hemligheten i resten av raden. Lösenfrasen registreras hos skrubbaren på varje upplåsningsväg, också när tjänsten kommer tillbaka från nyckelringen. Förut kunde den tjänsten köra i dagar utan att något var registrerat.

## En paus som betyder pausad

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="En pausad telefon mellan en bärbar dator hemma och en NAS på kontoret. Båda länkarna är markerade som av." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="En pausad telefon mellan en bärbar dator hemma och en NAS på kontoret. Båda länkarna är markerade som av." width="640" height="320"></picture>
</figure>

Att pausa bakgrundstjänsten brukade stoppa synken och lämna resten av enheten pratsam. Lyssnaren, fyren i det lokala nätverket, mötestjänsten, reläet och portmappningen i routern stannar nu med den, och de förblir stoppade tills du återupptar. En paus du själv har satt överlever en omstart, vilket spelar roll på en telefon som stoppar och startar tjänsten hela dagen. Den korta paus som `varsto disk` eller en import tar för sin egen skull sparas inte. Den tar slut när kommandot tar slut.

Miniatyrer i fillistan syns på telefoner igen. När motorn var upptagen svarade tjänsten förr ”ingen miniatyr”, och sidan trodde på det. Nu svarar den ”upptagen”, och sidan försöker igen.

Standardregeln kallar inte längre en mapp bruten i ett valv som inte har någon diskpool och ingen katalog som lagringsplats. Det finns en varning, att inget ligger på en disk som är din och hur du lägger till en. En regel du har satt med avsikt, som verkligen kräver en kopia hemma, hålls fortfarande till det. Samma skillnad gäller när en import avgör om dess källa får tas bort, så en mapp i det valvet väntar inte längre i evighet på en kopia på en disk du inte har.

Ett kommando och bakgrundstjänsten tar samma lås för att hämta, frigöra, skriva och flytta en fil, så de gör inte längre ogjort varandras tillstånd för mappen. En nedladdning eller en skrivning som misslyckas lämnar inte längre en fil `.varsto-tmp-…` eller `.varsto-upload-…` som håller en del av innehållet. Filer som kommer från en annan enhet behåller ändringstiden som den som skrev dem antecknade, i stället för att stämplas med ögonblicket de laddades ner. Verktyg som litar på datumet, ett bygge, ett fotobibliotek, en annan säkerhetskopia, slutar se varje hämtad fil som ny.

## En borttagen enhet förblir borttagen

En borttagen enhets mapposter, beviljanden och återställningsdeposition räknas bara fram till det första löpnummer den lämnade tomt. Den kan inte komma tillbaka senare och fylla luckan med en bakdaterad post. En medlem i ett annat valv tillämpar en borttagning som den läser ur mappepoken. En mapp som den som tog bort inte kunde nyckla om nycklas om vid nästa synk hos en ägare som fortfarande har nyckeln. Det den borttagna enheten redan har på sin egen disk får den behålla. Det var alltid sant, och det är fortfarande sant.

Anslutning läser organisationens manifest och tar valvepoker och återkallelser bara från dess administratörer. En återkallelse skriven av en vanlig medlem i förteckningen öppnar inte längre valvet för en enhet som ansluter.

Raden ”har ingen nyckel” i aktivitetsloggen har samma knapp som mappraden, så en telefon kan be om åtkomst från den raden i stället för att leta efter mappen. Restic-spegeln, och mapparna som anslutits under den, skapas så att bara den här användaren kan läsa dem.

## Namnet på ikonen

App-id:na är nu `net.varsto.app` på Android och macOS, `net.varsto.app.ios` på iOS och `net.varsto.app.alpha` för det osignerade macOS-bygget. En app som redan är installerad behåller sitt tidigare id, och dess valv flyttas inte, tills du installerar den igen. Att installera det nya paketet bredvid det gamla ersätter det inte.

## Om du kör alpha.16

Uppdatera när du vill. De två versionerna kan dela ett valv medan du gör det. Inget i den här versionen ber dig nollställa, skriva ut ett nytt återställningspaket eller avinstallera ett Android-bygge som redan är det releasesignerade från alpha.16. Om en delningsbegäran eller en organisationsbegäran fortfarande ligger i en klartextfil från alpha.16 förseglas den av nästa kommando som läser den. Det här är fortfarande en alfa.
