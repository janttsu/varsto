---
title: Alpha.12: kleine Dateien in Paketen, und Varsto auf Finnisch und Schwedisch
date: 2026-10-12
summary: Kleine verschlüsselte Blöcke werden jetzt in Paketen geschrieben, sodass ein Ordner mit 20.000 kleinen Dateien auf einem Bucket 79 Objekte wird statt 20.000. Oberfläche, Infobereich, Menüleiste, mobile Hüllen und diese Website gibt es auf Finnisch und Schwedisch wie auf Englisch.
---
Alpha.12 hat zwei Themen: weniger Objekte auf deinem Speicher, und die Oberfläche in mehr Sprachen.

## Kleine Blöcke in Paketen

Bisher war jeder verschlüsselte Block ein eigenes Objekt auf dem Speicher. Das ist einfach und robust, aber ein Ordner mit vielen kleinen Dateien, etwa Notizen, Quelltext oder die Beistelldateien einer Fotobibliothek, wird zu Zehntausenden winziger Objekte. Viele Anbieter rechnen je Anfrage ab, manche je Objekt, und sie alle aufzulisten und zu prüfen ist langsam.

Ab dieser Version werden Blöcke bis 128 KiB in Pakete von etwa 4 MiB oder 256 Einträgen gesammelt. Ein Paket wird mit einem Index geschrieben, der seine Einträge nennt und wo jeder anfängt, und ein Eintrag wird mit einer Bereichsanfrage gelesen, sodass das Lesen einer kleinen Datei weiter nur ihre eigenen Bytes herunterlädt. Große Blöcke werden weiter einzeln geschrieben. Pakete werden auf S3-Buckets, rclone-Remotes und Verzeichnissen benutzt; Kaltspeicher, Plattenpools und Überträger-Platten behalten einzelne Objekte.

Im Labor ging ein Ordner mit 20.000 kleinen Dateien als 79 Pakete auf den Bucket statt als 20.000 Objekte. Jeder Eintrag wurde nach dem Lauf gegen seinen Namen geprüft.

Einen Block zu löschen, der in einem Paket liegt, schreibt eine kleine Tot-Marke, und das Paket selbst geht weg, sobald jeder Eintrag weg ist. Reparatur, Prüfung, Repliken, Datenverschiebungen und das Entfernen eines Speichers verstehen alle Pakete. Das Speicherformat ist in Abschnitt 30 der [Formatspezifikation](../docs/alpha-0-format.html) beschrieben.

Mit älteren Versionen gibt es keine Kompatibilität: ein Gerät auf alpha.11 oder früher sieht Blöcke in Paketen nicht. Aktualisiere jedes Gerät.

## Unterwegs gefundene Korrekturen

Die Laborläufe fanden Probleme, die Unit-Tests übersehen hatten:

- `rclone serve s3` antwortet auf ein Bereichslesen mit Status 200 und nur den verlangten Bytes. Varsto nimmt das jetzt genauso an wie das übliche 206, sodass Pakete von solchen Servern richtig gelesen werden.
- Ein Gerät, das die Paketindexe gerade gelesen hatte, sah nicht noch einmal nach Paketen, die ein anderes Gerät Augenblicke später schrieb. Ein Lesen, das danebengeht, lädt die Indexe jetzt sofort neu.
- Ein Gerät konnte einem Paketindex trauen, nachdem ein anderes Gerät Einträge daraus gelöscht hatte. Bevor es entscheidet, dass ein Block schon existiert und nicht geschrieben werden muss, prüft Varsto jetzt, dass er noch in seinem Paket ist.
- Plattenpools und andere Speicher ohne Pakete schreiben ihre Blöcke wieder einzeln, sodass eine volle oder fehlende Platte als solche gemeldet wird, statt das ganze Hochladen scheitern zu lassen.
- Ein S3-Server, dessen Uhr mehr als ein paar Minuten danebenliegt, wird jetzt in beide Richtungen korrigiert, auch wenn er mit Status 400 statt 403 antwortet.

## Finnisch und Schwedisch

Die Desktop-Oberfläche, der Infobereich und die macOS-Menüleiste, die Hüllen für Android und iOS und diese Website gibt es jetzt auf Finnisch und Schwedisch. Englisch bleibt die Vorgabe. Die Sprache wählst du in den Einstellungen der Oberfläche oder unten in der Seitenleiste, und Infobereich und Apps folgen derselben Wahl. Die Kommandozeile, die Dokumentation und alles im Repository bleiben auf Englisch.

Übersetzungen der sicherheitskritischen Texte, etwa die zum Löschen, zum Widerrufen von Geräten und zu den Wiederherstellungswörtern, sind zur Prüfung durch Muttersprachler markiert. Korrekturen sind willkommen.

## Bau Varsto mit uns

Die neue Seite [Beitragen](../contribute/) beschreibt, wie Varsto gebaut wird und wo Hilfe gesucht wird: eine Prüfung der Kryptografie und des Speicherformats, Windows, iOS und Android, NAT-Durchgang in anderen Netzen als dem des Maintainers, mehr S3-Anbieter, Pakete und Übersetzungen.
