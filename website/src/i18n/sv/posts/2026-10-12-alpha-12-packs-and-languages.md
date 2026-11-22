---
title: Alpha.12: små filer i paket, och Varsto på finska och svenska
date: 2026-10-12
summary: Små krypterade block skrivs nu i paket, så en mapp med 20 000 små filer blir 79 objekt i en bucket i stället för 20 000. Gränssnittet, aktivitetsfältet, menyraden, mobilskalen och den här webbplatsen finns på finska och svenska likaväl som på engelska.
---
Alpha.12 har två teman: färre objekt på din lagring, och gränssnittet på fler språk.

## Små block i paket

Hittills var varje krypterat block ett eget objekt på lagringsplatsen. Det är enkelt och robust, men en mapp med många små filer, som anteckningar, källkod eller ett fotobiblioteks sidofiler, blir tiotusentals pyttesmå objekt. Många leverantörer tar betalt per anrop, en del per objekt, och att lista och kontrollera dem alla är långsamt.

Från den här versionen samlas block upp till 128 KiB i paket på ungefär 4 MiB eller 256 medlemmar. Ett paket skrivs med ett index som namnger medlemmarna och var var och en börjar, och en medlem läses med en intervalläsning, så att läsa en liten fil fortfarande bara laddar ner dess egna bytes. Stora block skrivs fortfarande ett och ett. Paket används på S3-buckets, rclone-fjärrlagringar och kataloger; kall lagring, diskpooler och överföringsdiskar behåller enstaka objekt.

I labbet gick en mapp med 20 000 små filer till bucketen som 79 paket i stället för 20 000 objekt. Varje medlem kontrollerades mot sitt namn efter körningen.

Att radera ett block som ligger i ett paket skriver en liten raderingsmarkör, och själva paketet försvinner när varje medlem är borta. Reparation, verifiering, repliker, dataflyttar och borttagning av lagringsplatser förstår alla paket. Lagringsformatet beskrivs i avsnitt 30 i [formatspecifikationen](../docs/alpha-0-format.html).

Det finns ingen kompatibilitet med äldre versioner: en enhet på alpha.11 eller tidigare ser inte block i paket. Uppdatera varje enhet.

## Fixar som hittades på vägen

Labbkörningarna hittade problem som enhetstesterna hade missat:

- `rclone serve s3` svarar på en intervalläsning med status 200 och bara de begärda bytena. Varsto godtar nu det likaväl som den vanliga 206, så paket läses rätt från sådana servrar.
- En enhet som just hade läst paketindexen tittade inte igen efter paket som en annan enhet skrev ögonblick senare. En läsning som missar laddar nu om indexen genast.
- En enhet kunde lita på ett paketindex efter att en annan enhet hade raderat medlemmar ur det. Innan Varsto bestämmer att ett block redan finns och inte behöver skrivas kontrollerar det nu att blocket fortfarande finns i sitt paket.
- Diskpooler och andra lagringsplatser utan paket skriver sina block ett i taget igen, så en full eller saknad disk rapporteras som sådan i stället för att hela sändningen misslyckas.
- En S3-server vars klocka går mer än några minuter fel korrigeras nu åt båda hållen, också när den svarar med status 400 i stället för 403.

## Finska och svenska

Skrivbordsgränssnittet, aktivitetsfältet och menyraden på macOS, skalen för Android och iOS och den här webbplatsen finns nu på finska och svenska. Engelska förblir standard. Språket väljs i gränssnittets inställningar eller längst ned i sidofältet, och aktivitetsfältet och apparna följer samma val. Kommandoraden, dokumentationen och allt i kodförrådet förblir på engelska.

Översättningar av de säkerhetskritiska texterna, till exempel de om att radera, återkalla enheter och återställningsord, är markerade för granskning av modersmålstalare. Rättelser tas gärna emot.

## Bygg Varsto med oss

Den nya sidan [Bidra](../contribute/) beskriver hur Varsto byggs och var hjälp behövs: en granskning av kryptografin och lagringsformatet, Windows, iOS och Android, NAT-traversering i andra nät än underhållarens, fler S3-leverantörer, paketering och översättningar.
