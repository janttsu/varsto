---
title: Alpha.7: Geräte mit einem Code koppeln, Finder-Aktionen und ein echter NAT-Weg
date: 2026-10-09
summary: Geräte koppeln sich jetzt aus der Oberfläche mit einem einmaligen Code, der Finder kann einen Platzhalter herunterladen oder mit einem Rechtsklick Platz freigeben, die macOS-App wird aus einem Disk-Image installiert, Geräte erreichen einander durch NAT, und Wechselplatten können einen Pool bilden.
---
Alpha.7 ist vor allem das Ergebnis, die Alpha einen Tag lang auf echten Geräten zu benutzen: ein Samsung-Telefon, ein Mac und ein Test-Bucket. Jeder Abschnitt unten hat als etwas angefangen, das nicht so funktionierte, wie es sollte.

## Ein Gerät mit einem Code koppeln

Ein Gerät hinzuzufügen hieß früher, einen Tresorschlüssel aus 64 Zeichen zu kopieren und die Einstellungen eines Speichers zu tippen, den beide Geräte erreichen. Jetzt zeigt das Gerät, das den Tresor schon hat, unter Geräte **Gerät hinzufügen**: einen Code aus neun Ziffern, der einmal gilt, zehn Minuten lang. Auf dem neuen Gerät wählst du **Mit deinem anderen Gerät koppeln**, tippst den Code, einen Namen und eine Passphrase, und das ist alles.

Die beiden Geräte finden einander im lokalen Netz, führen SPAKE2 aus, schlüsselgebunden durch den Code (eine falsche Vermutung lässt sich nicht offline prüfen, und drei falsche Codes schließen das Angebot), bestätigen den Schlüssel in beide Richtungen, und erst dann reist der Tresorschlüssel, mit den Speichereinstellungen und ihren Geheimnissen, versiegelt unter dem gemeinsamen Schlüssel. Das neue Gerät tritt über den ersten Speicher bei, den es erreichen kann. Wenn es im Netz nicht gefunden wird, funktioniert auch die Adresse unter dem Code. Derselbe Ablauf gibt es auf der Kommandozeile: `varsto pair offer` und `varsto pair join`.

## Der Finder kennt Platzhalter

Unter macOS gibt ein Rechtsklick auf Dateien **Mit Varsto herunterladen** oder **Mit Varsto Speicher freigeben**, und ein Doppelklick auf einen Platzhalter lädt die Datei herunter und öffnet sie. Platz freizugeben wird abgelehnt, außer jeder Block liegt auf einem Speicher *und* die Datei auf der Platte ist die Version, die synchronisiert wurde; vor dieser Version hätte eine Datei, die nach der letzten Synchronisierung geändert wurde, durch ihren Platzhalter ersetzt werden können. Der macOS-Download ist jetzt ein Disk-Image: öffne es und zieh Varsto in den Ordner Programme.

## Geräte erreichen einander durch NAT

Die Übertragung von Gegenstelle zu Gegenstelle funktionierte bisher im LAN und über weitergeleitete Ports. Jetzt erfahren Geräte ihre öffentliche Adresse mit STUN, schlagen über QUIC ein Loch durch das NAT, mit einem je Gerät angepinnten Zertifikat, und weichen darauf aus, über eines deiner eigenen erreichbaren Geräte weiterzuleiten. Getestet wurde zwischen einem Heimnetz und einem Cloud-Rechner hinter seinem eigenen NAT, in beide Richtungen, und mit blockiertem UDP, um das Relais zu erzwingen.

## Pools aus Wechselplatten

Ein Speicher kann ein Pool aus Wechselplatten sein: Varsto füllt sie nach freiem Platz mit einer Reserve, weiß, welche Platte welchen Block hält, bittet dich, eine bestimmte Platte anzuschließen, wenn es sie braucht, und zählt eine nicht angeschlossene Platte als Kopie nach dem Stand ihrer letzten Prüfung.

## Kleinere Dinge

- Aufbewahrungsregeln werden auf dem Desktop für jeden Ordner in einer Tabelle bearbeitet, und die volle Regel mit ihren Gründen ist sichtbar.
- Auf einem Telefon kannst du Dateien und Unterordner hinzufügen, eine Datei in einer anderen App öffnen oder teilen, und einen Ordner als einfache Dateien im internen Speicher halten statt verschlüsselt.
- Die Dateidetails sagen, ob dieses Gerät die Datei hat und welche Speicher sie halten.
- Das Fenster folgt einer Pause oder einer Synchronisierung, die aus der Menüleiste gestartet wurde.
- Das Beitreten nimmt die 24 Wiederherstellungswörter ebenso an wie den Hex-Schlüssel.

## Immer noch Alpha

Die Warnung auf jeder Seite gilt: die Kryptografie ist nicht auditiert, das Format kann sich noch ändern, und ein Fehler kann Daten zerstören. Nimm Testdaten und behalte eigene Sicherungen.
