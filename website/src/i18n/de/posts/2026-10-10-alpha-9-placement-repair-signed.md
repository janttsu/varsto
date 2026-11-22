---
title: Alpha.9: Daten, wo du sie haben willst, Reparatur von selbst, signierte Aktualisierungen, und jede Plattform öffentlich gebaut
date: 2026-10-10
summary: Ordner lassen sich auf gewählte Speicher legen und zwischen ihnen verschieben, verlorene Kopien werden von selbst repariert, Aktualisierungen sind mit einem Offline-Schlüssel signiert, Downloads von Gegenstelle zu Gegenstelle holen viele Blöcke auf einmal, und jedes Paket wird jetzt auf den Runnern von GitHub gebaut, getestet und fotografiert.
---
Alpha.9 (ein Build, der nie für sich markiert wurde; seine Änderungen kamen mit alpha.10) geht um die lange Strecke: zu entscheiden, wo Daten leben, sie ohne Aufforderung auf die Kopien zurückzubringen, die deine Regel verlangt, und der Aktualisierung zu vertrauen, die die nächste Version bringt.

## Daten, wo du sie haben willst

Jeder Ordner kann jetzt eine Platzierung haben: die Speicher, auf die seine Blöcke gehen. Daten lassen sich von einem Speicher auf einen anderen verschieben (ein ganzer Ordner, oder nur Dateien, die eine Anzahl Tage ungenutzt sind), Block für Block, jeder Block auf dem neuen Speicher geschrieben und zurückgelesen, bevor die alte Kopie gelöscht wird, und eine unterbrochene Verschiebung läuft einfach weiter, wenn du sie erneut startest. Ein Pool aus Wechselplatten kann Kopien auf Platten verlangen, die an verschiedenen Orten liegen, etwa eine zu Hause und eine bei der Arbeit, und Varsto füllt jede Platte mit dem, was ihrem Ort noch fehlt.

## Reparatur von selbst

Wenn eine Kopie fehlt, ein Speicher entfernt wird oder eine Prüfung scheitert, legt das Gerät, das die Daten hält, den Block dorthin zurück, wo Regel und Platzierung des Ordners ihn haben wollen, aus den eigenen Dateien, dem Zwischenspeicher verschlüsselter Blöcke, einem anderen Speicher oder einer Gegenstelle. Die Reparaturwarteschlange ist in der Oberfläche sichtbar und mit `varsto repair`.

## Signierte Aktualisierungen

Die Prüfsummenliste jeder Veröffentlichung ist jetzt mit dem Veröffentlichungsschlüssel des Projekts signiert, der nie den Rechner des Maintainers verlässt, und die Aktualisierung lehnt eine Veröffentlichung ab, die nicht damit signiert ist. Sie vergleicht die Prüfsumme außerdem mit der, die an der GitHub-Veröffentlichung hängt, ein zweiter Kanal. `varsto verify-release` prüft einen Download von Hand, und `minisign` auch. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) erklärt das Verfahren.

## Schneller von Gegenstelle zu Gegenstelle

Downloads halten bis zu acht Blöcke gleichzeitig unterwegs (damals), holen kleine Dateien in einem Ordner voraus und teilen sich eine Verbindung je Gegenstelle; ein Gerät, das Blöcke ausliefert, startet nicht mehr alle paar Sekunden eine eigene volle Synchronisierung. Die [Leistungsmessungen](../benchmarks/) vergleichen Paris, Amsterdam und Warschau, von Gegenstelle zu Gegenstelle gegen einen S3-Bucket.

## Offen gebaut

Jede Plattform wird jetzt bei jeder Änderung auf den Runnern von GitHub gebaut und getestet: die Pakete für Linux und Windows (das für Windows auf Windows Server 2025 getestet, einschließlich der Menüeinträge im Explorer), die Android-App im Emulator, das macOS-Disk-Image und die iOS-App auf Apple Silicon. Dieselben Läufe machen die [Bildschirmfotos](../screenshots/), sodass die Bilder auf dieser Website dem neuesten Build folgen.

## Und mehr

Die Freigabe hält am Fingerabdruck fest, wer Zugriff verlangt hat, das Entfernen eines Mitglieds legt die Freigabe auf neue Schlüssel, und ein Strongroom kann einen neuen Schlüssel bekommen; Dateien lassen sich aus dem Dateimanager unter Linux (Nautilus, Dolphin, Nemo) und Windows (Explorer) herunterladen oder den Platz freigeben; Ordnerzeilen behalten ihre zwei Hauptknöpfe und legen den Rest in ein Menü; die macOS-App und die Telefon-Apps sagen, wenn eine neuere Version auf der Download-Seite wartet, statt sich als aktuell zu bezeichnen; und große Hauptbuch-Stapel scheitern auf S3 nicht mehr.

## Aktualisiere jedes Gerät, bevor du Daten verschiebst

Das Verschieben von Daten schreibt eine neue Art Hauptbucheintrag, die alpha.8 und früher nicht lesen können: ihre Synchronisierungen würden ab der ersten Verschiebung scheitern. Aktualisiere zuerst alle deine Geräte. Ab dieser Version werden unbekannte Einträge übersprungen, sodass spätere Ergänzungen sie nicht mehr zerbrechen. Clients bis alpha.8 prüfen beim Aktualisieren nur die Prüfsumme; diese Version ist die erste, deren Aktualisierung auf der Signatur besteht.

## Immer noch Alpha

Die Kryptografie ist nicht auditiert, das Format kann sich noch ändern, und ein Fehler kann Daten zerstören. Nimm Testdaten und behalte eigene Sicherungen.
