---
title: Alpha.9: data där du vill ha den, reparation av sig själv, signerade uppdateringar, och varje plattform byggd öppet
date: 2026-10-10
summary: Mappar kan placeras på valda lagringsplatser och flyttas mellan dem, förlorade kopior repareras automatiskt, uppdateringar signeras med en nyckel som är offline, peer-to-peer-nedladdningar hämtar många block samtidigt, och varje paket byggs, testas och fotograferas nu på GitHubs runners.
---
Alpha.9 (ett bygge som aldrig taggades för sig; dess ändringar kom med i alpha.10) handlar om det långa loppet: att bestämma var data ska bo, att få tillbaka den till de kopior din regel kräver utan att bli tillsagd, och att lita på uppdateringen som kommer med nästa version.

## Data där du vill ha den

Varje mapp kan nu ha en placering: de lagringsplatser dess block ska till. Data kan flyttas från en lagringsplats till en annan (en hel mapp, eller bara filer som varit inaktiva ett antal dagar), block för block, varje block skrivet och läst tillbaka på den nya lagringsplatsen innan den gamla kopian raderas, och en avbruten flytt fortsätter helt enkelt när den körs igen. En pool av flyttbara diskar kan be om kopior på diskar som förvaras på olika platser, till exempel en hemma och en på jobbet, och Varsto fyller varje disk med det dess plats fortfarande saknar.

## Reparation av sig själv

När en kopia försvinner, en lagringsplats tas bort eller en verifiering misslyckas lägger enheten som har datan tillbaka blocket dit mappens regel och placering vill ha det, från sina egna filer, cachen med krypterade block, en annan lagringsplats eller en peer. Reparationskön syns i gränssnittet och med `varsto repair`.

## Signerade uppdateringar

Varje releases kontrollsummelista signeras nu med projektets releasenyckel, som aldrig lämnar underhållarens maskin, och uppdateraren vägrar en release som inte är signerad med den. Den jämför också kontrollsumman med den som hör till GitHub-releasen, en andra kanal. `varsto verify-release` kontrollerar en nedladdning för hand, och det gör `minisign` också. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) förklarar upplägget.

## Snabbare peer-to-peer

Nedladdningar håller upp till åtta block i gång (då), hämtar små filer i förväg genom en mapp och delar en anslutning per peer; en enhet som serverar block startar inte längre en full synk av sig själv med några sekunders mellanrum. [Prestandamätningarna](../benchmarks/) jämför Paris, Amsterdam och Warszawa, peer-to-peer mot en S3-bucket.

## Byggt öppet

Varje plattform byggs och testas nu på GitHubs runners vid varje ändring: Linux- och Windows-paketen (Windows-paketet testat på Windows Server 2025, inklusive menyposterna i Utforskaren), Android-appen i emulatorn, macOS-diskavbildningen och iOS-appen på Apple Silicon. Samma körningar tar [skärmbilderna](../screenshots/), så bilderna på den här webbplatsen följer det nyaste bygget.

## Och mer

Delning registrerar vem som bad om åtkomst via fingeravtryck, att ta bort en medlem flyttar delningen till nya nycklar, och ett Strongroom kan nycklas om; filer kan laddas ner eller frigöras från filhanteraren på Linux (Nautilus, Dolphin, Nemo) och Windows (Utforskaren); mapprader behåller sina två huvudknappar och lägger resten i en meny; macOS-appen och telefonapparna säger när en nyare version väntar på nedladdningssidan i stället för att kalla sig själva uppdaterade; och stora liggarbatcher misslyckas inte längre på S3.

## Uppdatera varje enhet innan du flyttar data

Att flytta data skriver en ny sorts liggarpost som alpha.8 och tidigare inte kan läsa: deras synkar skulle misslyckas från den första flytten. Uppdatera alla dina enheter först. Från den här versionen hoppas okända poster över, så senare tillägg slår inte sönder den. Klienter till och med alpha.8 kontrollerar bara kontrollsumman när de uppdaterar; den här versionen är den första vars uppdaterare kräver signaturen.

## Fortfarande alfa

Kryptografin har inte granskats, formatet kan fortfarande ändras, och en bugg kan förstöra data. Använd testdata och behåll egna säkerhetskopior.
