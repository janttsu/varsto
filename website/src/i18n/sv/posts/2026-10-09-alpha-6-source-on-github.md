---
title: Alpha.6: källkoden är offentlig, och varje plattform byggs i molnet
date: 2026-10-09
summary: Kodförrådet är nu offentligt på GitHub under licensen PolyForm Shield, de inbyggda apparna för macOS och iOS byggs på GitHub Actions, Linux, Windows och Android byggs på kortlivade molnmaskiner, och gränssnittet gjordes om kring en filvy.
---
Sedan alpha-0 har alforna lagt till det mesta av det planen kallar kärnan: lagringsplatser för S3 och rclone, delning med en annan användare via en förseglad nyckel, hybrida postkvantsignaturer och nyckelutbyte, lagringsregler som varnar i tid, peer-to-peer-överföring mellan dina egna enheter, komprimering före kryptering, Strongroom-mappar bakom en FIDO2-säkerhetsnyckel, ett utskrivbart återställningspaket och en MCP-server så att en assistent kan läsa och ordna om just de mappar du beviljar. Alpha.6 handlar om projektet runt den koden.

## Källkoden är offentlig

Kodförrådet finns på [github.com/janttsu/varsto](https://github.com/janttsu/varsto) under [PolyForm Shield License 1.0.0](../docs/licence.html): källkoden är tillgänglig, det är inte öppen källkod. Läs den, bygg den, rapportera det som går sönder i ärendehanteraren. Historiken skrevs om före publiceringen så att den inte bär några personliga sökvägar eller adresser; om du klonade en tidigare privat kopia, klona igen.

## Varje plattform byggs av en maskin som inte fanns en timme tidigare

- **macOS och iOS** byggs på GitHub Actions på Apple Silicon-runners: testsviten, den inbyggda Varsto.app med eget fönster, objekt i menyraden och medföljande kommandorad, och iOS-skalet för simulatorn, som startas där och fotograferas. En taggad release får macOS-zipen bifogad automatiskt.
- **Linux, Windows och Android** byggs och testas på kortlivade molnmaskiner som ett skript skapar, använder en gång och raderar: hela testsviten på en riktig Ubuntu, Windows-zipen installerad och körd på en riktig Windows Server, Android-APK:n byggd med SDK och NDK och sedan körd i en emulator.

Inget bygge beror längre på en utvecklares bärbara dator, vilket också betyder att varje paket på nedladdningssidan kommer från en dokumenterad väg som går att upprepa.

## En filvy först

Gränssnittet gjordes om: ett sidofält med ett mappträd, vyn Filer med sökvägsrad, statusrutor och en detaljpanel, och ett telefonläge där tabeller blir kort och navigeringen flyttas längst ned. På en telefon läggs en mapp till enbart med namn; enheten väljer var den ska ligga, så du skriver aldrig in en katalog. Det finns också ett spärrat ”Börja om på den här enheten” under Inställningar, för alfan, och översikten föreslår var inaktiva filer skulle vara billigare att ha kvar, utifrån Varstos egen uppgift om senaste användning och öppna prisdata.

## Fortfarande alfa

Inget här ändrar varningen på varje sida: kryptografin har inte granskats, formatet kan fortfarande ändras, och en bugg kan förstöra data. Använd testdata, behåll egna säkerhetskopior och läs [felmodellen](../docs/failure-model.html) innan du anförtror den något annat.
