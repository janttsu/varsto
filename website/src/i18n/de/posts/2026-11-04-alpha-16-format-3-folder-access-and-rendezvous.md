---
title: Alpha.16: Speicherformat 3, Ordnerzugriff nach Genehmigung und ein Rendezvous-Dienst
date: 2026-11-04
summary: Ein neues Speicherformat mit einem Hauptbuch auf Paketebene, signierten Datensätzen und Wiederherstellungswörtern, sodass vorhandene Tresore neu angelegt werden müssen; Ordner werden einem Gerät durch die Genehmigung eines Eigentümers geöffnet; Geräte finden einander über einen optionalen Rendezvous-Dienst; Beitritt und Mitgliedschaftsänderungen funktionieren offline; und Importe aus Torrents und YouTube.
---
Die aktuelle Version ist [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Diese Notiz beschreibt eine ältere Version. Die [Downloads](https://varsto.net/downloads/) stellen alpha.17 bereit, und der Quelltext liegt auf [GitHub](https://github.com/janttsu/varsto).

Alpha.16 ändert das Speicherformat noch einmal. Das ist die Hauptsache vor dem Aktualisieren: Tresore, die alpha.15 oder früher angelegt hat, lassen sich mit dieser Version nicht öffnen und müssen neu angelegt werden. Der Rest der Version ist eine lange Liste von Änderungen daran, wie Geräte beitreten, einander finden und mit einem schlechten Netz zurechtkommen, eine neue Seite Import, und ein großer Satz Korrekturen und Härtung aus einer Prüfung des neuen Formats.

## Einen Tresor neu anlegen

Es gibt keine Migration. Alpha.16 lehnt einen älteren Tresor ab, wenn es ihn öffnet oder wenn ein Gerät über seinen Speicher beitritt, und die Meldung sagt, was zu tun ist. Alpha.15 lehnt einen Tresor im Format 3 genauso ab, sodass die beiden Versionen einen Tresor in keiner Richtung teilen können. Jedes Gerät eines Tresors muss alpha.16 ausführen. Lass deine Dateien, wo sie sind, und dann:

1. Behalte die Programmdatei von alpha.15, falls du den alten Tresor noch lesen musst.
2. `varsto reset --yes` auf dem Gerät, dann `varsto init`. Es druckt einen Satz mit zwei Wortgruppen: die Tresorwörter und, neu in Format 3, die Wiederherstellungswörter. Bewahre beide auf.
3. Füge die Speicher wieder hinzu, füge die Ordner hinzu (hier werden die Wiederherstellungswörter verlangt) und synchronisiere.

## Android: die alte APK zuerst deinstallieren

Das Android-Paket ist jetzt eine release-signierte APK (`varsto-<version>-android.apk`), kein Debug-Build, sodass eine spätere Version sich als Aktualisierung darüberlegt. Sie ist mit einem neuen Schlüssel signiert. Eine Installation einer früheren Debug-APK (alpha.15 oder ein älterer täglicher Build) lässt sich nicht darauf aktualisieren: Android lehnt die Aktualisierung ab. Deinstalliere zuerst die alte App und installiere dann die neue. Das Deinstallieren entfernt die Tresorkopie dieses Geräts, also sorge vorher dafür, dass der Tresor ein anderes Gerät oder einen Speicher hat. Der tägliche Android-Download bleibt ein Debug-Build unter dem Namen `varsto-daily-android-debug.apk`.

## Speicherformat 3

Format 3 ist in Abschnitt 77 der Spezifikation und im Entwurfsdokument zu Format 3 beschrieben. Was es für dich ändert:

- Das Hauptbuch listet nicht mehr jeden Block. Es behauptet Pakete weniger fester Größen (256 KiB bis 64 MiB, aufgefüllt), sodass ein Speicher Größenklassen sieht und nicht, wie viele Blöcke oder Dateien es gibt.
- Jedes veröffentlichte Objekt außer einem Paket ist ein signierter Datensatz, der den Schlüssel nennt, mit dem er versiegelt ist. Manifeste, Papierkorb-Listen und Schnappschüsse sind eine Basis plus kleine Deltas, und jeder Ordner hält eine signierte Blockkarte je schreibendem Gerät.
- Ein Ordnerschlüssel erreicht ein Gerät nur als Gewährung, die ein Eigentümer genehmigt hat. Ein Gerät, das mit den Tresorwörtern beitritt, sieht Ordnernamen und hält keinen Inhalt; es fragt mit `varsto folder request`, ein Eigentümer vergleicht sechs Wörter, die auf beiden Geräten stehen, und genehmigt mit `varsto folder approve` (außerdem `requests`, `deny`, `members`, `role`). Der Hintergrunddienst genehmigt nie. Die Oberfläche hat auf der Seite Dateien eine Karte Ordnerzugriff.
- Jede Epoche eines Ordnerschlüssels hat eine Wiederherstellungskopie unter den Wiederherstellungswörtern. `varsto folder add` legt sie an, `varsto recovery escrow` schreibt eine fehlende später, und `varsto status` warnt bis dahin. `varsto join --recovery-words` öffnet jeden Ordner, der eine Wiederherstellungskopie hat.
- Gegenstellen sprechen nur TLS, mit Token, die an die Verbindung gebunden sind, und vergleichen die Spitzen des Hauptbuchs, sodass ein Speicher auffällt, der Stapel zurückhält oder zurücksetzt, und die Seite Hilfe und eine Benachrichtigung sagen es.
- Das Entfernen eines Geräts hält jetzt: ein widerrufenes Gerät bekommt den nächsten Ordnerschlüssel nicht, und seine Datensätze zählen ab der Entfernung nicht mehr.

## Einander finden: der Rendezvous-Dienst

Geräte können einander über Netze hinweg durch einen optionalen Rendezvous-Dienst finden, standardmäßig `https://varsto.net/rv`. Ein Gerät hinterlegt dort seinen versiegelten Gegenstellendatensatz, liest die Datensätze des Tresors, erfährt seine eigene öffentliche Adresse und erreicht, wenn keine Adresse antwortet, eine Gegenstelle durch einen koordinierten Lochschlag oder, als letzten Weg, ein Ende-zu-Ende verschlüsseltes Relais (angezeigt als `relayed via rendezvous`). Ein Gerät, das beitritt und in seinem Netz nichts findet, kann ein Angebot über den Code oder den Link nachschlagen und sich über das Relais koppeln. Der Dienst sieht Tags, IP-Adressen und Bytezahlen, nie die Identität des Tresors und keinen Inhalt. `varsto p2p rendezvous set <url> | on | --off | status` oder die Seite Gegenstellen ändert es, und der Server lässt sich selbst betreiben (`varsto-rendezvous`, eine statische Linux-Programmdatei im täglichen Build; der UDP-Port ist standardmäßig 3334). Alles funktioniert auch ohne ihn.

## Ein schlechtes Netz und offline arbeiten

- Ein Speicher, der nicht erreichbar ist, lässt eine ganze Synchronisierung nicht mehr scheitern. Er gilt für diesen Lauf als ausgefallen und ruht zwischen den Läufen, und die anderen Speicher machen weiter; was er verpasst hat, wird später dorthin kopiert.
- Aufrufe an S3 und rclone haben Zeitlimits, die zur Größe der Übertragung passen, Wiederholungen und fortsetzbare Mehrteil-Uploads, sodass eine langsame Leitung Sekunden kostet, nicht Minuten.
- Der Austausch von Gegenstelle zu Gegenstelle funktioniert ohne jeden Speicher, aus einem gespeicherten Gegenstellenverzeichnis, sodass die Synchronisierung im LAN ohne Internet funktioniert.
- Das Beitreten durch Koppeln braucht keinen Speicher mehr, der antwortet, und Änderungen der Mitgliedschaft (einen Ordner hinzufügen, genehmigen, eine Rolle ändern, freigeben) bleiben zuerst auf dem Gerät und gehen raus, wenn ein Speicher antwortet. `varsto status` sagt „N Änderungen warten auf den Upload“.
- Lokale Aktionen (Importe, die Seite Papierkorb, Vorschaubilder, Schreibvorgänge an Dateien) werden fertig, während ein Speicher aus ist, und melden „Upload ausstehend“.
- Oberfläche, Infobereich, Kommandozeile und MCP frieren nicht mehr ein, während eine Synchronisierung auf eine tote Verbindung wartet.

## Importe

- Eine Seite Import für jede Quelle (ein Ordner oder eine Platte, ein git-annex-Repository, ein Cloud-Laufwerk über rclone, ein Torrent, YouTube), mit einer Liste der laufenden Importe.
- `varsto import torrent` importiert Torrents, die größer sind als die Platte, in Stapeln, die eine Reserve an freiem Platz halten; eine Datei verlässt die Download-Platte erst, wenn ihre Blöcke auf einem Speicher liegen und die Regel des Ordners gilt.
- `varsto import youtube` archiviert Kanäle, Wiedergabelisten und Videos mit yt-dlp in Ordner, mit zurückhaltenden Vorgaben und einer Reserve an freiem Platz.

## Platten und Server

- `varsto mailbox` legt Blöcke von einer angedockten Platte für eine Pool-Platte oder einen Speicher bereit, der weg ist, in einem dauerhaften, per Hash geprüften Ausgangsfach, sodass ein Block, der nur auf Platte A liegt, Platte B erreicht, wenn B angedockt wird.
- `varsto service remember` funktioniert ohne Desktop-Sitzung (über SSH, auf Servern) durch `systemd-creds` oder den Kernel-Schlüsselbund; `varsto service forget` entfernt es.
- `varsto service stop` bleibt jetzt gestoppt, und eine Selbstaktualisierung startet den Dienst trotzdem neu.

## Korrekturen und Härtung

- Ein Abruf überschreibt keine Datei mehr, die nach dem Scan geändert wurde, und eine schlechte Datei stoppt Abruf oder Hochladen eines Ordners nicht mehr. Eine unlesbare Datei oder ein unlesbares Verzeichnis wird gezählt, statt dass Dateien darunter gelöscht aussehen.
- Mitgliedschaft: das Entfernen eines Geräts gilt für spätere Beitretende und für Ordner, die keinen neuen Schlüssel bekommen haben, und übernommen werden nur Epoche, Widerruf oder Löschauftrag eines Administrators.
- Entleeren, das Entfernen eines Speichers und das Aufräumen nach dem Einlegen einer Platte behalten jedes Paket, das die einzige Kopie sein könnte. Reparatur, Hochladen nach einem fehlenden Stapel und Anhängen nach einem Abhängen sind korrigiert.
- Bereichslesevorgänge bei S3 lassen `fsck` nicht mehr jedes Paket für zu kurz halten.
- Die Darstellung zeigt einen Hinweis beim Laden oder einen Hinweis auf einen leeren Tresor statt der Beispielszene, und Vorschaubilder erscheinen auf der Seite.
- TLS-Handshakes haben eine Frist, die hält, und eine Adresse kann höchstens 64 unvollendete halten. Ein hängender lokaler Client kann die lokale API nicht mehr einfrieren. Der Rendezvous-Server hat eine Ratenbegrenzung je Anfrageklasse und begrenzten Arbeitsspeicher für das Nachschlagen. Hinweise zu Abhängigkeiten, die `cargo audit` meldet, sind behoben.
- Die GitHub-Workflows laufen mit Nur-Lese-Rechten, außer dort, wo sie veröffentlichen.

## Kompatibilität

Jedes Gerät eines Tresors muss alpha.16 ausführen. Alpha.15 kann einen Tresor von alpha.16 nicht lesen, und alpha.16 kann einen Tresor von alpha.15 nicht lesen. Aktualisiere alle Geräte zusammen und lege den Tresor neu an, wie oben beschrieben. Das ist weiter eine Alpha: nichts für Produktionsdaten. Die volle Liste steht im Änderungsprotokoll.
