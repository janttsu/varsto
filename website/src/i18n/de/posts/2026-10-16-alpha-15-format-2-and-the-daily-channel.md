---
title: Alpha.15: Speicherformat 2, ein Windows-Installationsprogramm und ein täglicher Kanal
date: 2026-10-16
summary: Ein neues Speicherformat, das zwei Funde der Sicherheitsprüfung behebt, sodass vorhandene Tresore neu angelegt werden müssen; Windows bekommt ein Setup-Programm, ein natives Fenster und automatische Aktualisierungen; und ein signierter Kanal für tägliche Builds.
---
Die aktuelle Version ist [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Diese Notiz beschreibt eine ältere Version. Die [Downloads](https://varsto.net/downloads/) stellen alpha.17 bereit, und der Quelltext liegt auf [GitHub](https://github.com/janttsu/varsto).

Alpha.15 ändert das Speicherformat. Das ist die Hauptsache vor dem Aktualisieren: Tresore, die alpha.14 oder früher angelegt hat, lassen sich mit dieser Version nicht öffnen und müssen neu angelegt werden. Der Rest der Version ist eine lange Liste von Korrekturen und Arbeit an der Oberfläche, eine richtige Windows-Installation, und ein Kanal für tägliche Builds für Leute, die den neuesten Code testen wollen.

## Format 2 und was es bedeutet

Die Sicherheitsprüfung hinter alpha.14 fand zwei Probleme darin, wie Blöcke gespeichert wurden, die sich ohne Formatwechsel nicht beheben ließen. Format 2 behebt sie:

- Die Nonce eines verschlüsselten Blocks wird jetzt aus genau den Bytes abgeleitet, die verschlüsselt werden (nach der Kompression), nicht aus dem Klartext. Vorher hing die Nonce von einem Kompressionsergebnis ab, das über zstd-Versionen hinweg nicht garantiert gleich war.
- Das Schneiden ist je Ordner schlüsselgebunden. Die Schnittpunkte waren früher eine öffentliche Funktion des Dateiinhalts, sodass ein Speicher, der eine Datei kannte, sie an den Größen ihrer Blöcke wiedererkennen konnte. Jetzt wird dieselbe Datei in zwei Ordnern an anderen Stellen geschnitten.
- Jeder Block liegt in einem Paket (64 MiB, 256 MiB auf Kaltspeichern), und kein Block ist ein eigenes Objekt, sodass ein Speicher Paketgrößen sieht und nicht die Größen oder die Zahl der Blöcke darin. Pakete haben verschlüsselte Indexe, und gelöschte Blöcke werden je Ordner geführt und beim Umschreiben entfernt.
- Die Kompression ist zstd-Stufe 3 nach einer kurzen Probe: Text komprimiert fast so gut wie vorher und wird um ein Mehrfaches schneller geschrieben.

Was Format 2 nicht behebt: Dateilisten und Freigabe-Epochen werden weiter allein über den Ordnerschlüssel angenommen, weil das Schließen signierte Manifeste und Freigabe-Epochen braucht, und die gehören zur Datensatzschicht des nächsten Formats. Solange es das nicht gibt, kann, wer den Schlüssel eines Ordners hat, weiter ändern, was dieser Ordner zeigt, und nicht vertrauenswürdige Repliken und freigegebene Ordner solltest du so behandeln. Beide kritischen Funde bleiben in alpha.15 offen.

**Einen Tresor neu anlegen.** Es gibt keine Migration. Alpha.15 lehnt einen älteren Tresor ab, wenn es ihn öffnet oder wenn ein Gerät über seinen Speicher beitritt, und die Meldung sagt, was zu tun ist. Lass deine Dateien, wo sie sind, und dann:

1. Behalte die Programmdatei von alpha.14, falls du den alten Tresor noch lesen musst.
2. `varsto reset --yes` auf dem Gerät, dann `varsto init`.
3. Füge die Speicher wieder hinzu und synchronisiere die Ordner.

Alpha.14 lehnt einen Tresor im Format 2 genauso ab, sodass die beiden Versionen einen Tresor in keiner Richtung teilen können.

## Windows: das Installationsprogramm, ein natives Fenster und automatische Aktualisierungen

Das portable Zip ist weg. Windows hat jetzt einen Download, `Varsto-<version>-setup.exe`: er aktualisiert an Ort und Stelle, kann eine Installation reparieren, und sein Deinstallationsprogramm behält deinen Datenordner. Die Oberfläche öffnet sich in einem nativen Fenster (WebView2), Größe und Position bleiben gemerkt, ein Fenster je Benutzer, und der Infobereich startet es. Kopien, die das Setup-Programm installiert hat, suchen einmal am Tag nach Aktualisierungen, prüfen das signierte Setup-Programm und installieren es still. Wenn du noch eine entpackte portable Kopie laufen hast, sagt dir `varsto update`, das Installationsprogramm einmal auszuführen; danach laufen die Aktualisierungen von selbst weiter.

## Alles andere seit alpha.14

- Eine Ordnerübersicht mit einer Sicherheitsanzeige je Ordner: 100 % im externen Speicher, 100 % nur auf deinen eigenen Platten, teilweise geschützt oder nur auf Geräten.
- Eine Live-Darstellung von Geräten, Speichern, Platten und der Cloud mit animierten Flüssen, und echtes Vollbild im Browser und in den Hüllen für Android, macOS und Windows (Esc verlässt es).
- Weiterleiten: ein Gerät, das an einem Ordner hängt, auch mit selektiver Synchronisierung, kann die Blöcke anderer Geräte zu den Speichern tragen, auf die es schreiben kann, sodass die Fotos eines Telefons einen Bucket erreichen, für den nur der Laptop Zugangsdaten hat. Der Dialog zum Anhängen fragt jetzt nach voller oder selektiver Synchronisierung und nach der Richtung.
- Das Koppeln bietet jede nutzbare lokale Adresse an, die beste zuerst, und das Beitreten geht sie der Reihe nach durch und sucht im lokalen Netz, mit sichtbarem Fortschritt und einem Fehler, der nennt, was versucht wurde.
- Neue Daten bekommen eine Schonfrist, bevor die Prüfung eine Verletzung meldet: Blöcke, die innerhalb des größeren Werts aus Prüfungsfenster und 24 Stunden gespeichert wurden, erscheinen als „Prüfung ausstehend“.
- Die Oberfläche bleibt bei langen Synchronisierungen benutzbar: Lesevorgänge werden aus der letzten gemerkten Antwort beantwortet, wenn der Dienst beschäftigt ist, Listen werden schrittweise gezeichnet, und die Seite wird nie neu geladen.
- Korrekturen: Entleeren und Platzierung lehnen widersprüchliche Wahlen jetzt ab, Vorschaubilder für später hinzugefügte Speicher, Telefone nehmen nur S3- und rclone-Speicher an, Fotos und Videos, die schon auf einem Telefon sind, werden neueste zuerst gesichert, das Drucken des Wiederherstellungssatzes, das Dock-Symbol unter macOS, Zurück und die Tastatur unter Android, `reset` und Neustarts des Dienstes, und das Einrichten von Laufwerken mit einem modernen GPT-Layout.
- Ein unsigniertes iOS-`.ipa` für AltStore, SideStore und Sideloadly.
- Die Website hat eine französische Übersetzung, und die finnischen und schwedischen Seiten zeigen Bildschirmfotos der Oberfläche in ihrer eigenen Sprache.

## Der tägliche Kanal

`varsto update --daily` installiert den neuesten täglichen Build der Hauptlinie. Tägliche Builds werden für alle Plattformen gemacht, sobald sich der Hauptzweig bewegt, und unter varsto.net/daily/ veröffentlicht. Die Prüfsummenliste ist mit einem Daily-Schlüssel signiert, der vom Veröffentlichungsschlüssel getrennt ist: die Aktualisierung vertraut jedem Schlüssel nur für seinen eigenen Kanal, sodass eine Daily-Signatur nie eine Veröffentlichung bestätigt, und umgekehrt. Sie lehnt auch Listen ab, die veraltet sind, aus der Zukunft kommen oder älter sind als der Build, den du ausführst. Die Aktualisierung im Hintergrund und die Oberfläche bleiben bei den Veröffentlichungen; den täglichen Kanal startest du nur von Hand.

Tägliche Builds sind Entwicklungs-Builds. Sie sind nichts für Produktionsdaten, und ein täglicher Build kann eine Änderung des Speicherformats tragen, bevor es irgendeine Veröffentlichung tut.

## Kompatibilität

Jedes Gerät eines Tresors muss alpha.15 ausführen. Alpha.14 kann einen Tresor von alpha.15 nicht lesen, und alpha.15 kann einen Tresor von alpha.14 nicht lesen, und keines liest die Pakete oder die Tot-Marken-Listen des anderen. Aktualisiere alle Geräte zusammen und lege den Tresor neu an, wie oben beschrieben.
