---
title: Alpha.8: ein Hauptbuch, das klein bleibt, Geräte, die sich entfernen lassen, und Telefone, die nichts im Klartext behalten
date: 2026-10-09
summary: Das Hauptbuch listet jetzt nur, was neu ist, hält eine zwischengespeicherte Sicht und stutzt sich hinter signierten Prüfpunkten; Geräte lassen sich entfernen, mit neuen Schlüsseln für alles, was danach geschrieben wird; Telefone halten verschlüsselte Ordner als verschlüsselte Blöcke; und die Oberfläche zeigt, wo deine Daten sind und wie der Verkehr zwischen Gegenstellen fließt.
---
Alpha.8 kam aus einem langen Tag, alpha.7 auf einem Mac, einem Linux-Desktop und einem Samsung-Telefon zu benutzen, und aus der Frage, was mit dem Entwurf nach ein paar Jahren Nutzung geschieht.

## Ein Hauptbuch, das klein bleibt

Jedes Gerät führt ein signiertes, verschlüsseltes Protokoll von Tatsachen: welchen Block es wo gespeichert hat, welche Kopie es geprüft hat, welche Dateiliste es veröffentlicht hat. Bisher blieb jeder Eintrag für immer, als eigenes Objekt auf jedem Speicher, und jede Synchronisierung listete sie alle. Jetzt listet eine Synchronisierung nur, was neu ist, das Gerät hält eine zwischengespeicherte, verschlüsselte Sicht, statt alles nachzuspielen, eine Synchronisierung schreibt einen Stapel, und jedes Gerät schreibt regelmäßig einen signierten Prüfpunkt. Sobald alle deine Geräte einen Prüfpunkt bestätigt haben, werden die Stapel dahinter gelöscht, die letzten paar bleiben, sodass ein aus einer alten Sicherung wiederhergestelltes Gerät weiter erkannt wird. In einem Test-Tresor mit 20 000 Stapeln ging eine Synchronisierung ohne Neues von 668 ms auf 28 ms (damals) und das Hauptbuch auf dem Speicher von 171 MB auf 5 MB. Die Seite [So funktioniert es](../how-it-works/) erklärt das Hauptbuch.

## Ein Gerät entfernen

Ein verlorenes Telefon oder ein Laptop, den du nicht mehr benutzt, lässt sich von jedem anderen Gerät entfernen (Einstellungen oder Gegenstellen, „Entfernen…“, oder `varsto device revoke`). Seine späteren Einträge werden ignoriert, deine Geräte weisen seine Verbindungen zurück, und der Tresor wechselt auf neue Schlüssel, die nur deine verbleibenden Geräte bekommen, sodass nichts, was danach geschrieben wird, mit dem aufgeht, was das entfernte Gerät hält. Du kannst ihm auch befehlen, sich selbst zu löschen, wenn es das nächste Mal einen Speicher erreicht. Die Geräteliste zeigt System, Modell, Varsto-Version und letzte Synchronisierung jedes Geräts.

## Telefone halten verschlüsselte Ordner verschlüsselt

Ein Ordner, der „verschlüsselt auf diesem Telefon“ gehalten wird, hält jetzt nur verschlüsselte Blöcke, dieselben Bytes, die deine Speicher halten. Die selektive Synchronisierung funktioniert wie überall sonst; Dateien werden im eigenen Betrachter der App gezeigt, im Arbeitsspeicher entschlüsselt, und einer anderen App nur auf deine Bitte hin gegeben, als vorübergehende Kopie, die entfernt wird, wenn der Tresor sperrt. Android kann neue Fotos und Videos in einen Ordner deiner Wahl hochladen.

## Sehen, was geschieht

- **Wo deine Daten sind**: eine Grafik von Ordnern zu Speichern und Geräten, dazu wie viele Kopien alles hat.
- **Verkehr zwischen Gegenstellen**: welches Gerät was an welches schickt, über welchen Weg, mit welcher Geschwindigkeit.
- **Automatische Prüfung**: ein anderes Gerät liest deine Blöcke nach einem Zeitplan erneut, sodass eine Regel wie „innerhalb von 30 Tagen geprüft“ von selbst gilt.
- Knöpfe zeigen sofort, dass etwas angefangen hat, und Downloads zeigen ihren Fortschritt.

## Und mehr

Strongroom-Ordner lassen sich aus vorhandenen machen und bekommen einen Ersatz-Sicherheitsschlüssel; Speicher lassen sich entfernen, nachdem ihre Blöcke dorthin kopiert sind, wo sie gebraucht werden; Ordner lassen sich vom Tresor lösen oder aus ihm entfernen, und Namen auf der obersten Ebene sind eindeutig; Überträger-Platten kann ein Zielgerät gegeben werden; Speicherpreise speisen Kostenschätzungen und das Freigeben ungenutzter Dateien mit einem Klick; der Assistent (MCP) kann nie Dateien löschen oder überschreiben; und unter Linux installiert der erste Start Varsto für deinen Benutzer, mit einem Hintergrunddienst, der auch für Nutzer der Kommandozeile weiter synchronisiert.

## Immer noch Alpha

Die Kryptografie ist nicht auditiert, das Format kann sich noch ändern, und ein Fehler kann Daten zerstören. Nimm Testdaten und behalte eigene Sicherungen.
