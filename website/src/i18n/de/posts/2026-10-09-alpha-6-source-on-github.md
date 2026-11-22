---
title: Alpha.6: der Quelltext ist öffentlich, und jede Plattform baut in der Cloud
date: 2026-10-09
summary: Das Repository ist jetzt öffentlich auf GitHub unter der Lizenz PolyForm Shield, die nativen Apps für macOS und iOS bauen auf GitHub Actions, Linux, Windows und Android bauen auf kurzlebigen Cloud-Rechnern, und die Oberfläche wurde um eine Dateiansicht neu gemacht.
---
Seit alpha-0 haben die Alphas das meiste hinzugefügt, was der Plan den Kern nennt: Speicher über S3 und rclone, Freigabe an eine andere Person über einen versiegelten Schlüssel, hybride Post-Quanten-Signaturen und Schlüsselaustausch, Aufbewahrungsregeln, die rechtzeitig warnen, Übertragung von Gegenstelle zu Gegenstelle zwischen deinen eigenen Geräten, Kompression vor der Verschlüsselung, Strongroom-Ordner hinter einem FIDO2-Sicherheitsschlüssel, einen druckbaren Wiederherstellungssatz, und einen MCP-Server, damit ein Assistent genau die Ordner lesen und umordnen kann, die du gewährst. Alpha.6 geht um das Projekt um diesen Code herum.

## Der Quelltext ist öffentlich

Das Repository liegt unter [github.com/janttsu/varsto](https://github.com/janttsu/varsto) unter der [PolyForm Shield License 1.0.0](../docs/licence.html): Quelltext einsehbar, nicht Open Source. Lies ihn, bau ihn, melde im Issue-Tracker, was bricht. Die Historie wurde vor der Veröffentlichung umgeschrieben, sodass sie keine persönlichen Pfade oder Adressen trägt; wenn du eine frühere private Kopie geklont hast, klone erneut.

## Jede Plattform baut ein Rechner, den es eine Stunde vorher nicht gab

- **macOS und iOS** bauen auf GitHub Actions auf Apple-Silicon-Runnern: die Testsuite, das native Varsto.app mit eigenem Fenster, Eintrag in der Menüleiste und mitgelieferter Kommandozeile, und die iOS-Hülle für den Simulator, die dort gestartet und fotografiert wird. Eine markierte Veröffentlichung bekommt das macOS-Zip automatisch angehängt.
- **Linux, Windows und Android** bauen und testen auf kurzlebigen Cloud-Rechnern, die ein Skript anlegt, einmal benutzt und löscht: die volle Testsuite auf einem echten Ubuntu, das Windows-Zip installiert und auf einem echten Windows Server durchgespielt, die Android-APK mit dem SDK und dem NDK gebaut und dann in einem Emulator ausgeführt.

Kein Build hängt mehr an einem Entwickler-Laptop, und das heißt auch, dass jedes Paket auf der Download-Seite aus einem dokumentierten, wiederholbaren Weg kommt.

## Zuerst eine Dateiansicht

Die Oberfläche wurde neu gemacht: eine Seitenleiste mit einem Ordnerbaum, eine Ansicht Dateien mit Brotkrumen, Zustandskästchen und einem Detailbereich, und ein Telefonmodus, in dem Tabellen zu Karten werden und die Navigation nach unten wandert. Auf einem Telefon wird ein Ordner nur über den Namen hinzugefügt; das Gerät wählt, wo er liegt, sodass du nie ein Verzeichnis tippst. In den Einstellungen gibt es für die Alpha außerdem ein abgesichertes „auf diesem Gerät neu anfangen“, und die Übersicht schlägt vor, wo ungenutzte Dateien günstiger liegen würden, aus Varstos eigener Aufzeichnung der letzten Nutzung und offenen Preisdaten.

## Immer noch Alpha

Nichts hier ändert die Warnung auf jeder Seite: die Kryptografie ist nicht auditiert, das Format kann sich noch ändern, und ein Fehler kann Daten zerstören. Nimm Testdaten, behalte eigene Sicherungen, und lies das [Fehlermodell](../docs/failure-model.html), bevor du ihm etwas anderes anvertraust.
