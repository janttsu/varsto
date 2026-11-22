---
title: Alpha.8: en liggare som förblir liten, enheter som kan tas bort, och telefoner som inte sparar något i klartext
date: 2026-10-09
summary: Liggaren listar nu bara det som är nytt, håller en cachad vy och rensar sig själv bakom signerade kontrollpunkter; enheter kan tas bort med nya nycklar för allt som skrivs efteråt; telefoner håller krypterade mappar som krypterade block; och gränssnittet visar var dina data finns och hur peer-to-peer-trafiken flyter.
---
Alpha.8 kom ur en lång dag med alpha.7 på en Mac, en Linux-dator och en Samsung-telefon, och ur frågan vad som händer med designen efter några års användning.

## En liggare som förblir liten

Varje enhet för en signerad, krypterad logg över fakta: vilket block den lagrade var, vilken kopia den verifierade, vilken fillista den publicerade. Hittills blev varje post kvar för alltid, som ett eget objekt på varje lagringsplats, och varje synk listade alla. Nu listar en synk bara det som är nytt, enheten håller en cachad, krypterad vy i stället för att spela upp allt, en synk skriver en batch, och varje enhet skriver då och då en signerad kontrollpunkt. När alla dina enheter har kvitterat en kontrollpunkt raderas batcherna bakom den, och de sista behålls så att en enhet som återställts från en gammal säkerhetskopia fortfarande fångas. I ett testvalv med 20 000 batcher gick en synk utan något nytt från 668 ms till 28 ms (då) och liggaren på lagringen från 171 MB till 5 MB. Sidan [Så fungerar det](../how-it-works/) förklarar liggaren.

## Ta bort en enhet

En borttappad telefon eller en bärbar dator du inte längre använder kan tas bort från vilken annan enhet som helst (Inställningar eller Peers, ”Ta bort…”, eller `varsto device revoke`). Dess senare poster ignoreras, dina enheter vägrar dess anslutningar, och valvet går över till nya nycklar som bara dina kvarvarande enheter får, så inget som skrivs efteråt öppnas med det den borttagna enheten har. Du kan också beordra den att rensa sig själv nästa gång den når en lagringsplats. Enhetslistan visar varje enhets system, modell, Varsto-version och senaste synk.

## Telefoner håller krypterade mappar krypterade

En mapp som hålls ”krypterad på den här telefonen” innehåller nu bara krypterade block, samma bytes som dina lagringsplatser har. Selektiv synkronisering fungerar som överallt annars; filer visas i appens egen visare, dekrypterade i minnet, och lämnas till en annan app bara när du ber om det, som en tillfällig kopia som tas bort när valvet låses. Android kan ladda upp nya foton och videor till en mapp du väljer.

## Se vad som händer

- **Var dina data finns**: ett diagram från mappar till lagringsplatser och enheter, med hur många kopior allt har.
- **Peer-to-peer-trafik**: vilken enhet som skickar vad till vilken, via vilken väg och i vilken hastighet.
- **Automatisk verifiering**: en annan enhet läser om dina block enligt ett schema, så att en regel som ”verifierad inom 30 dagar” håller av sig själv.
- Knappar visar genast att något har startat, och nedladdningar visar hur långt de har kommit.

## Och mer

Strongroom-mappar kan göras av befintliga och får en reservsäkerhetsnyckel; lagringsplatser kan tas bort efter att deras block har kopierats dit de behövs; mappar kan kopplas loss eller tas bort från valvet, och namn på översta nivån är unika; överföringsdiskar kan ges en målenhet; lagringspriser ger kostnadsuppskattningar och frigör inaktiva filer med ett klick; assistenten (MCP) kan aldrig radera eller skriva över filer; och på Linux installerar första starten Varsto för din användare, med en bakgrundstjänst som fortsätter synka även för den som bara använder kommandoraden.

## Fortfarande alfa

Kryptografin har inte granskats, formatet kan fortfarande ändras, och en bugg kan förstöra data. Använd testdata och behåll egna säkerhetskopior.
