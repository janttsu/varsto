---
title: Alpha.14: eine Sicherheitsprüfung, ihre Korrekturen, und alles, was seit alpha.13 zusammengeführt wurde
date: 2026-10-14
summary: Eine Sicherheitsprüfung des ganzen Programms auf Code-Ebene, die Korrekturen, die sie verlangt hat, eine viel schnellere Synchronisierung, fortsetzbare Verschiebungen auf einen Stapel Wechselplatten, und die rund zwanzig Funktionen, die seit alpha.13 auf dem Hauptzweig gewartet hatten.
---
Die aktuelle Version ist [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Diese Notiz beschreibt eine ältere Version. Die [Downloads](https://varsto.net/downloads/) stellen alpha.17 bereit, und der Quelltext liegt auf [GitHub](https://github.com/janttsu/varsto).

Alpha.14 ist die bisher größte Version. Sie trägt zweierlei: den Rückstand an Funktionen, die nach alpha.13 auf dem Hauptzweig gelandet sind, und die erste Runde Korrekturen aus einer Sicherheitsprüfung, die jede Zeile des Programms gelesen hat, mit einem feindlichen Speicher, einem feindlichen Netz und einem feindlichen Gerät im selben Tresor im Sinn.

## Die Sicherheitsprüfung

Die Prüfung fand die kryptografischen Grundbausteine in Ordnung und die Berechtigung darum herum mangelhaft. Alpha.14 schließt die Teile, die sich ohne Änderung des Speicherformats schließen ließen:

- Hauptbuch-Ereignisse werden nach Rolle angenommen: eine Replik darf nur Kopien behaupten, ein Mitglied eines freigegebenen Ordners darf nur über diesen Ordner sprechen, und Prüfpunkte kommen nur von vollwertigen Geräten. Ein Speicher, der einen Stapel zurückhält, fällt auf, ein Schrottobjekt unter dem eigenen Namen eines Geräts sperrt das Gerät nicht mehr aus, und ein Widerruf zählt nur zusammen mit seiner signierten Schlüsselepoche.
- Der Dienst und der Transport zwischen Gegenstellen: der STUN-Nebenkanal ist begrenzt, der Browser bekommt einen einmaligen Startcode statt des Sitzungstokens, eine gebastelte Anfrage kann die API nicht mehr abstürzen lassen, Strongroom-Schlüssel müssen zu einer festgelegten Bindung passen und der Sicherheitsschlüssel fragt nach seiner PIN, Geheimnisse sind von der Kommandozeile verschwunden, die Aktualisierung lehnt veraltete signierte Listen ab, und Lesevorgänge vom Speicher sind begrenzt.
- Hygiene: Schlüsseldateien sind vom ersten Byte an privat, Token werden in konstanter Zeit verglichen, Schlüsselmaterial wird aus dem Arbeitsspeicher gelöscht, Wiederherstellungsanteile tragen eine Prüfung, und die Shamir-Bibliothek wurde durch einen korrigierten Fork ersetzt.

Zwei Funde brauchen ein neues Speicherformat und sind nicht in dieser Version: Dateilisten und Freigabe-Epochen werden weiter allein über den Ordnerschlüssel angenommen, und die Nonce des Stücks kommt weiter aus dem Klartext. Beides ist auf den Zweigen für Format 2 gebaut, und das ist die nächste Version. Bis dahin behandle freigegebene Ordner und nicht vertrauenswürdige Repliken so, wie die Prüfung es beschreibt: wer den Schlüssel eines Ordners hat, kann weiter ändern, was dieser Ordner zeigt.

## Schneller

50 000 kleine Dateien auf einen lokalen Speicher zu synchronisieren ging von 167 Sekunden auf 21; 10 000 Dateien von 77 auf 8,5. Die Uhr wird nicht mehr je Datei auf die Platte geschrieben, Speicher werden einmal je Synchronisierung geöffnet, Uploads gehen je Speicher parallel hinaus, der S3-Client prüft einmal, ob bedingte Schreibvorgänge eingehalten werden, und die Programmdateien werden mit Link-Zeit-Optimierung und einem schnelleren Zuteiler gebaut.

## Alles seit alpha.13

Live-Aktivität zwischen Geräten, die Bitfäule-Prüfung, ganze Laufwerke für Plattenpools, Sicherungen mit restic, Dateianalysen und `varsto search`, eingeschränkte MCP-Schlüssel, Neuaufbau des Hauptbuchs, medienbewusste Prüfung, Plattenbuchführung und „die nächste Platte zum Andocken“, die Anleitung zum Wiederherstellungssatz, Importe aus git-annex, Cloud-Laufwerken und lokalen Ordnern, der tresorweite Papierkorb, Speicherkontingente und Entleeren, lokale Debug-Protokolle, ursprüngliche Namen, Ordnersicherheit (Markierung, Schutz vor Massenlöschung, nur senden und nur empfangen), Ignorierregeln, Dateimetadaten, Versionsverlauf, QR-Einladungen, Portweiterleitung am Router, freier Mindestplatz auf der Platte, der Ereignisstrom, Nur-Lese-Mitglieder, Plattformregeln, Änderungsverlauf, und fortsetzbare Verschiebungen eines Ordners auf einen Stapel Wechselplatten, eine Platte nach der anderen.

## Kompatibilität

Das Speicherformat ist unverändert, aber jedes Gerät eines Tresors muss alpha.14 ausführen: der Zwischenspeicher der Hauptbuch-Sicht und die Prüfungen der Datensätze haben sich geändert, und ältere Geräte lesen nicht, was alpha.14 schreibt. Die Torrent-Download-Funktion auf dem Hauptzweig gehört nicht zu dieser Version.
