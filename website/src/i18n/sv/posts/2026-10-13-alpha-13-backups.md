---
title: Alpha.13: säkerhetskopior som ingenting kan ändra
date: 2026-10-13
summary: Välj en mapp på valfri enhet så håller Varsto krypterade, skrivskyddade versioner av den på dina externa lagringsplatser, aldrig på dina enheter, i så många dagar du väljer (90 som standard). Återställningar går till en katalog du namnger, från appen eller kommandoraden.
---
Synkronisering håller varje kopia likadan, vilket är precis det du inte vill när en fil raderas av misstag eller krypteras av utpressningsprogram: skadan når varje enhet. Alpha.13 lägger till säkerhetskopior, som fungerar åt andra hållet.

## Så fungerar det

Du väljer en mapp på en enhet och ger säkerhetskopian ett namn. Varsto tar en version av den: fillistan och varje block, krypterade som allt annat det lagrar. Versionerna går bara till externa lagringsplatser (S3-buckets, rclone-fjärrlagringar, NAS-utdelningar, kataloger och kall lagring), aldrig till överföringsdiskar och aldrig till dina andra enheter. Dina andra enheter ser att säkerhetskopian finns och vilka versioner den har, men de laddar inte ner innehållet.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Versioner tas dagligen som standard, varje vecka eller bara när du ber om det (`varsto backup take`). Block som inte ändrats lagras en gång, hur många versioner som än använder dem.

## Skrivskyddade och sparade en bestämd tid

En version redigeras aldrig efter att den tagits. Dess utgångsdatum förseglas inuti den när den skrivs, så att ändra lagringstiden senare påverkar bara nya versioner. När en version har gått ut raderar enheten som gjorde säkerhetskopian den från lagringsplatserna. Bara block som ingen kvarvarande version behöver raderas, och en dags frist tar hänsyn till klockor som är lite fel. Om den enheten är borta gör någon annan enhet i valvet det lite senare. Att stoppa en säkerhetskopia tar inga nya versioner men raderar ingenting i förtid.

## Återställa

En återställning går alltid till en katalog du namnger, och den katalogen måste vara tom om du inte tillåter överskrivning. Du kan välja den nyaste versionen, en numrerad eller den nyaste på eller före ett datum, och återställa allt eller bara vissa sökvägar. Appen har sidan Säkerhetskopior som gör samma sak.

## Detaljer och gränser

Formatet finns i avsnitt 31 i [specifikationen](../docs/alpha-0-format.html). I den här första versionen följer utgången varje enhets egen klocka, lagringsregler täcker inte säkerhetskopior ännu, och vyn Var dina data finns visar dem inte.

Äldre versioner förstår inte säkerhetskopior: uppdatera varje enhet i ett valv till alpha.13 innan du lägger till en.
