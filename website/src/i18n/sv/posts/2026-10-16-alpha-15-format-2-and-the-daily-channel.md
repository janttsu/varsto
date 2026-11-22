---
title: Alpha.15: lagringsformat 2, ett Windows-installationsprogram och en daglig kanal
date: 2026-10-16
summary: Ett nytt lagringsformat som åtgärdar två fynd från säkerhetsgranskningen, så befintliga valv måste skapas på nytt; Windows får ett installationsprogram, ett eget fönster och automatiska uppdateringar; och en signerad kanal för dagliga byggen.
---
Den aktuella versionen är [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Den här texten beskriver en äldre version. [Nedladdningarna](https://varsto.net/downloads/) ger alpha.17, och källkoden finns på [GitHub](https://github.com/janttsu/varsto).

Alpha.15 ändrar lagringsformatet. Det är det viktigaste att veta innan du uppdaterar: valv som gjorts av alpha.14 eller tidigare kan inte öppnas av den här versionen och måste skapas på nytt. Resten av versionen är en lång lista med fixar och arbete i gränssnittet, en riktig Windows-installation och en kanal för dagliga byggen för den som vill testa den nyaste koden.

## Format 2 och vad det betyder

Säkerhetsgranskningen bakom alpha.14 hittade två problem i hur block lagrades som inte kunde åtgärdas utan att ändra formatet. Format 2 åtgärdar dem:

- Nonce för ett krypterat block härleds nu från de exakta bytes som krypteras (efter komprimering), inte från klartexten. Förut berodde nonce på ett komprimeringsresultat som inte var garanterat att bli detsamma mellan olika versioner av zstd.
- Bitindelaren är nycklad per mapp. Skärpunkterna var förr en publik funktion av filinnehållet, så en lagringsplats som kände en fil kunde känna igen den på storlekarna hos dess block. Nu skärs samma fil i två mappar på olika ställen.
- Varje block lagras i ett paket (64 MiB, 256 MiB på kalla lagringsplatser) och inget block är ett eget objekt, så en lagringsplats ser paketstorlekar och inte storlekarna eller antalet block inuti dem. Paketen har krypterade index, och raderade block hålls reda på per mapp och skrivs bort.
- Komprimeringen är zstd nivå 3 efter en snabb sondering: text komprimeras nästan lika bra som förut och är flera gånger snabbare att skriva.

Vad format 2 inte åtgärdar: fillistor och delningsepoker godtas fortfarande enbart på mappnyckeln, eftersom det kräver signerade manifest och delningsepoker, som hör till postlagret i nästa format. Tills det finns kan den som har en mapps nyckel fortfarande ändra vad den mappen visar, och opålitliga repliker och delade mappar ska behandlas så. Båda de kritiska fynden är fortfarande öppna i alpha.15.

**Skapa valvet på nytt.** Det finns ingen migrering. Alpha.15 vägrar ett äldre valv när det öppnar det eller när en enhet ansluter via dess lagringsplats, och meddelandet säger vad du ska göra. Låt filerna ligga kvar där de är, och gör sedan så här:

1. Behåll alpha.14-binären om du kan behöva läsa det gamla valvet.
2. `varsto reset --yes` på enheten, sedan `varsto init`.
3. Lägg till lagringsplatserna igen och synka mapparna.

Alpha.14 vägrar ett valv i format 2 på samma sätt, så de två versionerna kan inte dela ett valv åt något håll.

## Windows: installationsprogrammet, ett eget fönster och automatiska uppdateringar

Den portabla zipen är borta. Windows har nu en nedladdning, `Varsto-<version>-setup.exe`: den uppgraderar på plats, kan reparera en installation, och dess avinstallerare behåller din datamapp. Gränssnittet öppnas i ett eget fönster (WebView2) med storlek och position ihågkomna, ett fönster per användare, och aktivitetsfältet startar det. Kopior som installationsprogrammet har installerat söker uppdateringar en gång om dagen, verifierar det signerade installationsprogrammet och installerar det tyst. Om du fortfarande kör en uppackad portabel kopia säger `varsto update` att du ska köra installationsprogrammet en gång; sedan fortsätter uppdateringarna av sig själva.

## Allt annat sedan alpha.14

- En mappöversikt med en säkerhetsindikator per mapp: 100 % i extern lagring, 100 % endast på dina egna diskar, delvis skyddad eller endast på enheter.
- En levande visualisering av enheter, lagringsplatser, diskar och molnet med animerade flöden, och riktig helskärm i webbläsaren och i skalen för Android, macOS och Windows (Esc lämnar den).
- Vidarebefordran: en enhet som är ansluten till en mapp, även med selektiv synkronisering, kan bära andra enheters block till de lagringsplatser den kan skriva till, så att en telefons foton når en bucket som bara den bärbara datorn har inloggningsuppgifter till. Dialogen Anslut frågar nu om full eller selektiv synkronisering och om riktningen.
- Ihopparning erbjuder varje användbar lokal adress, den bästa först, och anslutning faller tillbaka över dem och en sökning i det lokala nätverket, med synligt förlopp och ett fel som namnger vad som prövades.
- Ny data får en frist innan verifieringen rapporterar ett brott: block som lagrats inom det större av verifieringsfönstret och 24 timmar visas som ”verifiering väntar”.
- Gränssnittet förblir användbart under långa synkar: läsningar besvaras från det senaste sparade svaret när tjänsten är upptagen, listor ritas stegvis, och sidan laddas aldrig om.
- Fixar: tömning och placering vägrar nu motsägelsefulla val, miniatyrer för lagringsplatser som lagts till senare, telefoner godtar bara S3- och rclone-lagringsplatser, foton och videor som redan finns på en telefon säkerhetskopieras nyast först, utskrift av återställningspaketet, Dock-ikonen på macOS, Tillbaka och tangentbordet på Android, `reset` och omstarter av tjänsten, och initiering av diskar med en modern GPT-layout.
- En osignerad iOS-`.ipa` för AltStore, SideStore och Sideloadly.
- Webbplatsen har en fransk översättning, och de finska och svenska sidorna visar skärmbilder av gränssnittet på sitt eget språk.

## Den dagliga kanalen

`varsto update --daily` installerar det nyaste dagliga bygget av huvudlinjen. Dagliga byggen görs för alla plattformar när huvudgrenen rör sig och publiceras på varsto.net/daily/. Kontrollsummelistan signeras med en daglig nyckel som är skild från releasenyckeln: uppdateraren litar på varje nyckel bara för dess egen kanal, så en daglig signatur validerar aldrig en release, och tvärtom. Den vägrar också listor som är föråldrade, från framtiden eller äldre än bygget du kör. Bakgrundsuppdateraren och gränssnittet stannar på releaser; den dagliga kanalen startas bara för hand.

Dagliga byggen är utvecklingsbyggen. De är inte för produktionsdata, och ett dagligt bygge kan bära en ändring av lagringsformatet innan någon release gör det.

## Kompatibilitet

Varje enhet i ett valv måste köra alpha.15. Alpha.14 kan inte läsa ett valv från alpha.15 och alpha.15 kan inte läsa ett valv från alpha.14, och ingendera läser den andras paket eller tombstone-listor. Uppdatera alla enheter tillsammans och skapa valvet på nytt som beskrivs ovan.
