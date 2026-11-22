---
title: Alpha.16: lagringsformat 3, mappåtkomst genom godkännande och en mötestjänst
date: 2026-11-04
summary: Ett nytt lagringsformat med en liggare på paketnivå, signerade poster och återställningsord, så befintliga valv måste skapas på nytt; mappar öppnas för en enhet genom en ägares godkännande; enheter hittar varandra via en valfri mötestjänst; anslutning och medlemsändringar fungerar offline; och import från torrents och YouTube.
---
Den aktuella versionen är [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Den här texten beskriver en äldre version. [Nedladdningarna](https://varsto.net/downloads/) ger alpha.17, och källkoden finns på [GitHub](https://github.com/janttsu/varsto).

Alpha.16 ändrar lagringsformatet igen. Det är det viktigaste att veta innan du uppdaterar: valv som gjorts av alpha.15 eller tidigare kan inte öppnas av den här versionen och måste skapas på nytt. Resten av versionen är en lång lista med ändringar i hur enheter ansluter, hittar varandra och klarar ett dåligt nätverk, en ny sida Import, och en stor mängd fixar och härdning från en granskning av det nya formatet.

## Skapa valvet på nytt

Det finns ingen migrering. Alpha.16 vägrar ett äldre valv när det öppnar det eller när en enhet ansluter via dess lagringsplats, och meddelandet säger vad du ska göra. Alpha.15 vägrar ett valv i format 3 på samma sätt, så de två versionerna kan inte dela ett valv åt något håll. Varje enhet i ett valv måste köra alpha.16. Låt filerna ligga kvar där de är, och gör sedan så här:

1. Behåll alpha.15-binären om du kan behöva läsa det gamla valvet.
2. `varsto reset --yes` på enheten, sedan `varsto init`. Den skriver ut ett återställningspaket med två uppsättningar ord: valvorden och, nytt i format 3, återställningsorden. Spara båda.
3. Lägg till lagringsplatserna igen, lägg till mapparna (återställningsorden efterfrågas här) och synka.

## Android: avinstallera den gamla APK:n först

Android-paketet är nu en releasesignerad APK (`varsto-<version>-android.apk`), inte ett debug-bygge, så en senare release installeras över den som en uppdatering. Den är signerad med en ny nyckel. En installation av en tidigare debug-APK (alpha.15, eller ett äldre dagligt bygge) kan inte uppdateras till den: Android vägrar uppdateringen. Avinstallera den gamla appen först och installera sedan den nya. Avinstallation tar bort den enhetens kopia av valvet, så se till att valvet har en annan enhet eller en lagringsplats innan du gör det. Den dagliga Android-nedladdningen förblir ett debug-bygge under namnet `varsto-daily-android-debug.apk`.

## Lagringsformat 3

Format 3 beskrivs i avsnitt 77 i specifikationen och i designdokumentet för format 3. Det som ändras för dig:

- Liggaren listar inte längre varje block. Den gör anspråk på paket av några fasta storlekar (256 KiB till 64 MiB, utfyllda), så en lagringsplats ser storleksklasser och inte hur många block eller filer det finns.
- Varje publicerat objekt utom ett paket är en signerad post som namnger nyckeln den är förseglad med. Fillistor, papperskorgslistor och versioner är en bas plus små deltan, och varje mapp har en signerad blockkarta per skrivande enhet.
- En mappnyckel når en enhet bara som ett beviljande som en ägare har godkänt. En enhet som ansluter med valvorden ser mappnamn och har inget innehåll; den ber med `varsto folder request`, en ägare jämför sex ord som visas på båda enheterna och godkänner med `varsto folder approve` (också `requests`, `deny`, `members`, `role`). Bakgrundstjänsten godkänner aldrig. Gränssnittet har kortet Åtkomst till mappar på sidan Filer.
- Varje epok av mappnyckeln har en återställningskopia under återställningsorden. `varsto folder add` gör den, `varsto recovery escrow` skriver en som saknas senare, och `varsto status` varnar tills dess. `varsto join --recovery-words` öppnar varje mapp som har en återställningskopia.
- Peers talar bara TLS, med token bundna till anslutningen, och jämför liggarens huvuden, så en lagringsplats som undanhåller eller rullar tillbaka batcher märks, och sidan Hjälp och en avisering säger det.
- Att ta bort en enhet håller i sig nu: en återkallad enhet får inte nästa mappnyckel, och dess poster slutar räknas vid borttagningen.

## Hitta varandra: mötestjänsten

Enheter kan hitta varandra över nätverk via en valfri mötestjänst, som standard `https://varsto.net/rv`. En enhet lämnar sin förseglade peer-post där, läser valvets poster, får reda på sin egen publika adress och, när ingen adress svarar, når en peer genom ett samordnat hole punching eller, som sista väg, ett totalsträckskrypterat relä (visas som `relayed via rendezvous`). En enhet som ansluter och inte hittar något i sitt nätverk kan slå upp ett erbjudande med kod eller länk och paras ihop via reläet. Tjänsten ser taggar, IP-adresser och antal byte, aldrig valvets identitet eller innehåll. `varsto p2p rendezvous set <url> | on | --off | status` eller sidan Peers ändrar den, och du kan driva servern själv (`varsto-rendezvous`, en statisk Linux-binär i det dagliga bygget; standardporten för UDP är 3334). Allt fungerar också utan den.

## Ett dåligt nätverk och att arbeta offline

- En lagringsplats som inte kan nås får inte längre en hel synk att misslyckas. Den markeras som nere för körningen och vilar mellan körningar, och de andra lagringsplatserna fortsätter; det den missade kopieras dit senare.
- Anrop till S3 och rclone har tidsgränser som följer överföringens storlek, nya försök och multipart-uppladdningar som kan återupptas, så en långsam länk kostar sekunder, inte minuter.
- Peer-to-peer fungerar utan någon lagringsplats, från en sparad peer-katalog, så synk i det lokala nätverket fungerar utan internet.
- Att ansluta genom ihopparning behöver inte längre att en lagringsplats svarar, och medlemsändringar (lägga till en mapp, godkänna, byta roll, dela) sparas först på enheten och skickas när en lagringsplats svarar. `varsto status` säger ”N ändringar väntar på uppladdning”.
- Lokala åtgärder (importer, sidan Papperskorg, miniatyrer, filskrivningar) blir klara medan en lagringsplats är nere och rapporterar ”uppladdning väntar”.
- Gränssnittet, aktivitetsfältet, kommandoraden och MCP fryser inte längre medan en synk väntar på en död länk.

## Importer

- En sida Import för varje källa (en mapp eller disk, ett git-annex-arkiv, en molnlagring via rclone, en torrent, YouTube), med en lista över importer som pågår.
- `varsto import torrent` importerar torrentfiler som är större än disken i omgångar som håller en reserv för ledigt utrymme; en fil lämnar nedladdningsdisken först när dess block finns på en lagringsplats och mappens regel håller.
- `varsto import youtube` arkiverar kanaler, spellistor och videor till mappar med yt-dlp, med varsamma standardvärden och en reserv för ledigt utrymme.

## Diskar och servrar

- `varsto mailbox` mellanlagrar block från en dockad disk åt en pooldisk eller lagringsplats som är borta, i en beständig utkorg som kontrolleras med hash, så ett block som bara finns på disk A når disk B när B dockas.
- `varsto service remember` fungerar utan en skrivbordssession (över SSH, på servrar) via `systemd-creds` eller kärnans nyckelring; `varsto service forget` tar bort det.
- `varsto service stop` förblir nu stoppad, och en självuppdatering startar ändå om tjänsten.

## Fixar och härdning

- En hämtning skriver inte längre över en fil som redigerats efter avläsningen, och en trasig fil stoppar inte längre en mapps hämtning eller sändning. En oläsbar fil eller katalog räknas i stället för att få filerna under den att se raderade ut.
- Medlemskap: borttagning av en enhet gäller för den som ansluter senare och för mappar som inte nycklades om, och bara en administratörs epok, återkallelse eller raderingsorder antas.
- Tömning, borttagning av en lagringsplats och uppstädningen efter att en disk satts i behåller varje paket som kan vara den enda kopian. Reparation, sändning efter en saknad batch och anslutning efter frånkoppling är rättade.
- Intervalläsningar mot S3 får inte längre `fsck` att kalla varje paket för kort.
- Visualiseringen visar en notis om laddning eller en notis om tomt valv i stället för exempelscenen, och miniatyrer syns på sidan.
- TLS-handskakningar har en tidsgräns som håller, och en adress kan ha högst 64 ofärdiga. En lokal klient som har fastnat kan inte längre frysa det lokala API:t. Mötestjänstens server har en gräns per förfrågningsklass och begränsat minne för uppslag. Sårbarhetsråd som `cargo audit` rapporterar är åtgärdade.
- GitHub-arbetsflödena körs med enbart läsrättigheter utom där de publicerar.

## Kompatibilitet

Varje enhet i ett valv måste köra alpha.16. Alpha.15 kan inte läsa ett valv från alpha.16 och alpha.16 kan inte läsa ett valv från alpha.15. Uppdatera alla enheter tillsammans och skapa valvet på nytt som beskrivs ovan. Det här är fortfarande en alfa: inte för produktionsdata. Hela listan finns i ändringsloggen.
