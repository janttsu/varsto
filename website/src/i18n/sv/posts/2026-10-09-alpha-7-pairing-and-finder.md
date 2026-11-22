---
title: Alpha.7: para ihop enheter med en kod, Finder-åtgärder och en riktig väg genom NAT
date: 2026-10-09
summary: Enheter paras nu ihop från gränssnittet med en engångskod, Finder kan ladda ner en platshållare eller frigöra utrymme med ett högerklick, macOS-appen installeras från en diskavbildning, enheter når varandra genom NAT, och flyttbara diskar kan bilda en pool.
---
Alpha.7 är mest resultatet av att ha kört alfan på riktiga enheter en dag: en Samsung-telefon, en Mac och en testbucket. Varje avsnitt nedan började som något som inte fungerade som det skulle.

## Para ihop en enhet med en kod

Att lägga till en enhet betydde förr att kopiera en valvnyckel på 64 tecken och skriva in inställningarna för en lagringsplats som båda enheterna når. Nu visar enheten som redan har valvet **Lägg till en enhet** under Enheter: en kod på nio siffror som fungerar en gång, i tio minuter. På den nya enheten väljer du **Para ihop med din andra enhet**, skriver koden, ett namn och en lösenfras, och det är allt.

De två enheterna hittar varandra i det lokala nätverket, kör SPAKE2 nycklad av koden (en felaktig gissning kan inte kontrolleras offline, och tre felaktiga koder stänger erbjudandet), bekräftar nyckeln i båda riktningarna, och först då färdas valvnyckeln, med lagringsinställningarna och deras hemligheter, förseglad under den delade nyckeln. Den nya enheten ansluter via den första lagringsplats den når. Om den inte hittas i nätverket fungerar adressen som visas under koden också. Samma flöde finns på kommandoraden: `varsto pair offer` och `varsto pair join`.

## Finder känner till platshållare

På macOS högerklickar du filer för **Ladda ner med Varsto** eller **Frigör utrymme med Varsto**, och dubbelklickar en platshållare för att ladda ner filen och öppna den. Att frigöra utrymme nekas om inte varje block finns på en lagringsplats *och* filen på disken är den version som synkades; före den här versionen kunde en fil som redigerats efter senaste synken ha bytts ut mot sin platshållare. Nedladdningen för macOS är nu en diskavbildning: öppna den och dra Varsto till Program.

## Enheter når varandra genom NAT

Peer-to-peer-överföring fungerade förr i det lokala nätverket och genom vidarebefordrade portar. Nu tar enheterna reda på sin publika adress med STUN, tar sig igenom NAT över QUIC med ett certifikat som är fäst per enhet, och faller tillbaka på att gå via en av dina egna nåbara enheter. Det testades mellan ett hemnätverk och en molnmaskin bakom sin egen NAT, åt båda hållen, och med UDP blockerat för att tvinga fram reläet.

## Pooler av flyttbara diskar

En lagringsplats kan vara en pool av flyttbara diskar: Varsto fyller dem efter ledigt utrymme med en reserv, vet vilken disk som har vilket block, ber dig ansluta en bestämd disk när den behöver en, och räknar en disk som är offline som en kopia enligt dess senaste kontroll.

## Mindre saker

- Lagringsregler redigeras för varje mapp i en tabell på skrivbordet, och hela regeln och dess skäl syns.
- På en telefon kan du lägga till filer och undermappar, öppna en fil i en annan app eller dela den, och hålla en mapp som vanliga filer i den interna lagringen i stället för krypterad.
- Fildetaljerna säger om den här enheten har filen och vilka lagringsplatser som har den.
- Fönstret följer en paus eller en synk som startats från menyraden.
- Anslutning godtar de 24 återställningsorden likaväl som hexnyckeln.

## Fortfarande alfa

Varningen på varje sida står kvar: kryptografin har inte granskats, formatet kan fortfarande ändras, och en bugg kan förstöra data. Använd testdata och behåll egna säkerhetskopior.
