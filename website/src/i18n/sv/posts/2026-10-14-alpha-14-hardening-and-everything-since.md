---
title: Alpha.14: en säkerhetsgranskning, dess fixar och allt som kommit in sedan alpha.13
date: 2026-10-14
summary: En säkerhetsgranskning av hela programmet på kodnivå, fixarna den begärde, en mycket snabbare synk, flyttar som kan återupptas till en stapel flyttbara diskar, och de drygt tjugo funktioner som hade väntat på huvudgrenen sedan alpha.13.
---
Den aktuella versionen är [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Den här texten beskriver en äldre version. [Nedladdningarna](https://varsto.net/downloads/) ger alpha.17, och källkoden finns på [GitHub](https://github.com/janttsu/varsto).

Alpha.14 är den största versionen hittills. Den bär två saker: funktionerna som hade samlats på hög och landade på huvudgrenen efter alpha.13, och den första omgången fixar från en säkerhetsgranskning som läste varje rad i programmet med en fientlig lagring, ett fientligt nätverk och en fientlig annan enhet i åtanke.

## Säkerhetsgranskningen

Granskningen fann de kryptografiska primitiverna sunda och behörigheten runt dem bristfällig. Alpha.14 stänger de delar som kunde stängas utan att ändra lagringsformatet:

- Liggarhändelser godtas efter roll: en replik får bara påstå kopior, en medlem i en delad mapp får bara tala om den mappen, och kontrollpunkter tas enbart från fullvärdiga enheter. En lagringsplats som undanhåller en batch märks, ett skräpobjekt under en enhets eget namn spärrar inte längre enheten, och en återkallelse räknas bara tillsammans med sin signerade nyckelepok.
- Tjänsten och peer-transporten: STUN-sidokanalen är begränsad, webbläsaren får en engångskod för start i stället för sessionstoken, en tillverkad förfrågan kan inte längre krascha API:t, Strongroom-nycklar måste stämma med ett åtagande och säkerhetsnyckeln ber om sin PIN, hemligheter är borta från kommandoraden, uppdateraren vägrar föråldrade signerade listor, och läsningar från lagringen är begränsade.
- Hygien: nyckelfiler skapas privata från första byten, token jämförs i konstant tid, nyckelmaterial raderas från minnet, återställningsandelar bär en kontroll, och Shamir-biblioteket byttes mot ett rättat fork.

Två fynd kräver ett nytt lagringsformat och finns inte i den här versionen: fillistor och delningsepoker godtas fortfarande enbart på mappnyckeln, och bitens nonce kommer fortfarande från klartexten. Båda är byggda på grenarna för format 2, som är nästa version. Tills dess, behandla delade mappar och opålitliga repliker som granskningen beskriver: den som har en mapps nyckel kan fortfarande ändra vad den mappen visar.

## Snabbare

Att synka 50 000 små filer till en lokal lagringsplats gick från 167 sekunder till 21; 10 000 filer från 77 till 8,5. Klockan skrivs inte längre till disk per fil, lagringsplatser öppnas en gång per synk, uppladdningar sprids per lagringsplats, S3-klienten undersöker en gång om villkorliga skrivningar respekteras, och binärerna byggs med länktidsoptimering och en snabbare allokator.

## Allt sedan alpha.13

Aktivitet i realtid mellan enheter, kontrollen av bitröta, hela diskar för diskpooler, säkerhetskopior med restic, filanalyser och `varsto search`, avgränsade MCP-nycklar, ombyggnad av liggaren, verifiering som tar hänsyn till mediet, diskbokföring och ”nästa disk att docka”, guiden för återställningspaketet, import från git-annex, molnlagringar och lokala mappar, papperskorgen för hela valvet, lagringskvoter och tömning, lokala felsökningsloggar, ursprungliga namn, mappsäkerhet (markör, skydd mot massradering, endast skicka och endast ta emot), ignoreringsregler, filmetadata, versionshistorik, QR-inbjudningar, portmappning i routern, minsta lediga diskutrymme, händelseströmmen, skrivskyddade medlemmar, plattformsregler, ändringshistorik, och flyttar av en mapp som kan återupptas till en stapel flyttbara diskar, en disk i taget.

## Kompatibilitet

Lagringsformatet är oförändrat, men varje enhet i ett valv måste köra alpha.14: cachen för liggarvyn och postkontrollerna ändrades, och äldre enheter läser inte det alpha.14 skriver. Funktionen för torrentnedladdning på huvudgrenen ingår inte i den här versionen.
