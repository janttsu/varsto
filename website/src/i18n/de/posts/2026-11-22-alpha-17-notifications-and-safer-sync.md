---
title: Alpha.17: der Tresor bleibt, die stillen Fehler gehen
date: 2026-11-22
summary: Kein neues Speicherformat und keine neuen Wörter zum Aufschreiben. Alpha.17 ist die Version, die eine fehlgeschlagene Synchronisierung davon abhält, Dateien zu löschen, die letzte Sicherung behält und deinem Telefon sagt, wenn wirklich etwas nicht stimmt.
---
Dieses Mal aktualisierst du ohne Zeremonie. Alpha.17 öffnet einen Tresor von alpha.16 so, wie er ist. Es gibt kein neues Format, keinen zweiten Satz Wörter und nichts, das du neu anlegen müsstest. Was sich ändert, ist die Art Fehler, die passierte, während du woanders hingeschaut hast.

Ein Abruf, der nie zu Ende kam, konnte trotzdem Löschungen von Dateien veröffentlichen, die dieses Gerät nicht gelesen hatte. Der neueste Schnappschuss einer Sicherung konnte allein wegen seines Alters ablaufen und die einzige wiederherstellbare Kopie mitnehmen. Das erste Treffen mit einem anderen Gerät konnte eine Viertelstunde dasitzen und tot aussehen. Dafür ist diese Version da. Es ist weiter eine Alpha, und weiter nichts für Daten, die du nicht verlieren darfst. Die lange Liste steht im Änderungsprotokoll. Was du wirklich merkst, steht unten.

## Dein Telefon hört davon

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="Ein Laptop schickt eine Warnung wegen knappen Platzes zum Ordner Dokumente an ein Telefon. Der Tresor selbst bleibt auf dem Computer." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="Ein Laptop schickt eine Warnung wegen knappen Platzes zum Ordner Dokumente an ein Telefon. Der Tresor selbst bleibt auf dem Computer." width="640" height="320"></picture>
</figure>

Ein Gerät kann deinem Telefon jetzt über ntfy, Pushover oder Telegram sagen, wenn etwas einen Menschen braucht. Füge einen Kanal in den Einstellungen oder mit `varsto notify` hinzu. Jeder Dienst hat eine kurze Anleitung und eine Testnachricht, und du wählst, was er sagen darf. Ordnernamen, Speichernamen und Gerätenamen können aus dem Text bleiben.

Die Warnungen, auf die es ankommt, sind an, bis du sie ausmachst: ein Speicher in Schwierigkeiten, eine Platte, der der Platz ausgeht, weniger Kopien, als eine Regel verlangt, beschädigte Daten, eine Sicherung, die fehlgeschlagen oder überfällig ist, eine Anfrage, die auf dich wartet. Fertige Sicherungen, neue Dateien und eine Tageszusammenfassung bleiben still, bis du sie verlangst. Die Token liegen auf dem Gerät, in `notify.json`, und werden nie synchronisiert. Die Nachricht selbst ist auf dem Weg durch ntfy, Pushover oder Telegram nicht Ende zu Ende verschlüsselt, und das solltest du wissen, bevor du sie einen Ordner nennen lässt. Ein fehlgeschickter Versand wartet und wird erneut versucht, auch nach einem Neustart. Dieselbe Warnung wird sechs Stunden lang nicht wiederholt, und ein Kanal bekommt höchstens zwanzig Nachrichten in der Stunde. Du kannst das einrichten, während der Tresor gesperrt ist.

## Ein Abruf, der die Bytes schon hat

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Geheimtext-Blöcke bleiben auf dem Laptop. Eine einzige Verbindung trägt nur die fehlenden Blöcke zu einer gesperrten Cloud." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Geheimtext-Blöcke bleiben auf dem Laptop. Eine einzige Verbindung trägt nur die fehlenden Blöcke zu einer gesperrten Cloud." width="640" height="320"></picture>
</figure>

Das meiste einer geänderten Datei war schon hier. Alpha.17 holt diese Blöcke nicht noch einmal. Die unveränderten Stücke einer geänderten Datei kommen von der vorherigen Version auf der Platte. Eine Umbenennung oder eine Verschiebung kommt vom alten Pfad, oder aus dem Papierkorb, wenn sie dorthin gegangen ist. Zwei Kopien derselben Datei holen jeden unterschiedlichen Block einmal. Alles, was lokal gelesen wird, wird gegen seine Stückkennung geprüft, und ein Block, der nicht passt, wird am Ende doch geholt.

Die andere Hälfte ist das Gerät, das die Datei gerade geschrieben hat. Es gibt jede Datei, die es an ihren Platz gelegt hat, den anderen sofort, nicht erst wenn die eigene Synchronisierung zu Ende ist, und die Anfragen werden auf die Gegenstellen verteilt, die die Blöcke wirklich haben.

Wenn dieses Gerät ein anderes zum ersten Mal trifft, bevor jenes dieses Zertifikat gelesen hat, wird der Weg als verbindend gezeigt und sofort erneut versucht. Eine spätere Ablehnung wartet ein paar Sekunden und wird als unerreichbar gezeigt. Ein Gerät, das noch nie geantwortet hat, verbringt nicht mehr eine Minute und dann bis zu fünfzehn, bevor der erste echte Versuch kommt. Solange diese erste Synchronisierung noch läuft, wird ein Ordner ohne Dateien als holend gezeigt. Es ist kein leerer Ordner, der schon fertig ist.

Eine Gegenstelle, die geantwortet hat und dann ausfällt, ruht eine Sekunde, und die Ruhe verdoppelt sich, statt einer pauschalen Minute. Ein Block, den sonst niemand hat, wird bei dieser Gegenstelle noch einmal angefragt. Wenn die Gegenstelle neu startet, beendet die nächste Synchronisierung, ein neuerer Gegenstellendatensatz oder eine LAN-Bake die Ruhe, statt jede Datei als nicht verfügbar zu melden. Geräte, die einfach weg sind, ruhen länger, und bis zu acht von ihnen werden zusammen gefragt, sodass sie eine Zeitüberschreitung kosten statt acht.

## Was ein Fehlschlag nicht mehr darf

Ein Abruf, der scheitert, veröffentlicht keine Löschungen von Dateien mehr, die dieses Gerät nicht gelesen hat. Was du hier hinzugefügt oder geändert hast, wird weiter hochgeladen. Der nächste Abruf holt die Kopien, die die anderen Geräte noch haben, bevor eine fehlende Datei für weg erklärt werden kann.

Wenn die Version eines anderen Geräts einen Konflikt gewinnt, rückt die Datei hier erst beiseite, wenn der Gewinner wirklich angekommen ist. Ein Gewinner, der nicht geholt werden konnte, ließ den Pfad früher leer, und das nächste Hochladen veröffentlichte dann eine Löschung davon. Eine Datei, die wächst oder schrumpft, während der Scan sie liest, wartet auf den nächsten Scan. Sie wird nicht mit einer Größe veröffentlicht, die ihre Blöcke nicht hergeben, was früher jedes andere Gerät die ganze Liste des Ordners ablehnen ließ.

Nicht beanspruchte Pakete werden nach 48 Stunden gelöscht, oder nach 24, wenn ein lokaler Speicher zu weniger als 10 Prozent frei ist. Es waren sieben Tage. Ein Hochladen, ein Import oder eine Sicherung, deren Kartendatensatz nie veröffentlicht wurde, löscht die Pakete, die gerade geschrieben wurden, und dasselbe tut eine Reparatur, deren Stapel nicht versiegelt wurde. Wenn das Versiegeln scheitert, nachdem der Kartendatensatz veröffentlicht wurde, bleiben die Pakete, weil die Behauptung schon im Hauptbuch steht. `varsto gc orphans` löscht nicht beanspruchte Pakete jetzt, wenn du nicht warten willst.

Die Aufbewahrung einer Sicherung frisst den neuesten Schnappschuss nicht mehr, nur weil er alt ist. Ein verlorenes Quellverzeichnis, oder ein Gerät, das nie einen neueren genommen hat, ließ diesen Schnappschuss früher planmäßig ablaufen und sammelte dann seine Blöcke ein, und es blieb nichts zum Wiederherstellen. Eine Sicherung zu stoppen lässt den letzten Schnappschuss weiter ablaufen. Dieser Teil ist unverändert, und so sagst du, dass du damit fertig bist.

## Uhren, Namen und ein Schlüssel, der das Gerät überlebt hat

Zwei Prozesse auf einem Rechner, die Kommandozeile und der Hintergrunddienst, können nicht mehr denselben Lamport-Wert reservieren und ihn dann beide ausgeben. Die Reservierung hält eine Sperre über das Lesen, das Erhöhen und das Ersetzen.

Zwei Geräte, die dieselbe Epochennummer für den Tresor oder einen Ordner schreiben, hören nicht mehr auf zu signieren, bis ein Mensch wählt. Das Gerät, das beide Datensätze sieht, behält den mit der größeren Kennung des Ausstellers. `varsto device resolve-epoch` und `varsto folder resolve-epoch` ersetzen diese Wahl weiter, wenn du eine andere willst.

Auf einer Platte, die Groß- und Kleinschreibung ignoriert, bekommen zwei Pfade, die sich nur in der Schreibung oder in der Unicode-Normalisierung unterscheiden, unterschiedliche lokale Namen, egal welcher zuerst ankommt. Bei Gleichstand gewinnt die NFC-Schreibung. Dann behält der kleinere ursprüngliche Pfad den schlichten Namen, und der andere wird ` (2)`.

Ein Gerät zu entfernen ändert für sich nicht das Passwort beim Speicheranbieter. Was es jetzt tut, ist sich zu weigern zu vergessen. `varsto status` und `varsto device list` nennen jeden Speicher, dessen Zugangsdaten dieses Gerät noch nutzen könnte, um Geheimtext zu löschen. Wenn du sie beim Anbieter ersetzt hast, löscht `varsto storage mark-rotated <name>` die Warnung. Varsto wechselt das Geheimnis nicht für dich.

## Die Wörter auf Papier, und die Schlüssel, die in einer Datei lagen

`varsto recovery kit` druckt den Satz von Format 3: die Tresorwörter und die Wiederherstellungswörter. Früher druckte es den Text von Format 2, der sagte, die 24 Tresorwörter läsen alles im Tresor. In Format 3 öffnen sie Gerätenamen, Ordnernamen und das Hauptbuch auf dem Speicher. Inhalt braucht die Wiederherstellungswörter. Ein Ausdruck ohne sie sagt das jetzt in Großbuchstaben, statt vollständig auszusehen. `--shares` teilt beide Sätze.

Eine Freigabeanfrage und eine Organisationsanfrage hielten ihre privaten Schlüssel früher in einer JSON-Datei im Klartext. Eine Kopie des Geräteverzeichnisses, genommen während die Anfrage wartete, konnte sie lesen und, sobald der Eigentümer genehmigt hatte, den Ordner ganz ohne Passphrase öffnen. Die Schlüssel sind jetzt unter der Passphrase des Geräts versiegelt. Den Anforderungscode zu zeigen fragt danach, und die Anfrage anzunehmen fragt noch einmal. Eine Anfrage, die alpha.16 im Klartext liegen ließ, wird versiegelt, wenn ein Befehl sie das nächste Mal liest.

Protokolle bekommen dieselbe Behandlung für die Art, wie ein Debug-Drucker einen optionalen Wert schreibt. Eine Zeile wie `password: Some("…")` wurde früher am Anführungszeichen abgeschnitten und ließ das Geheimnis im Rest der Zeile. Die Passphrase wird auf jedem Entsperrweg beim Bereiniger registriert, auch wenn der Dienst aus dem Schlüsselbund zurückkommt. Vorher konnte dieser Dienst tagelang laufen, ohne dass etwas registriert war.

## Eine Pause, die Pause bedeutet

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="Ein pausiertes Telefon zwischen einem Laptop zu Hause und einem NAS im Büro. Beide Verbindungen sind als aus markiert." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="Ein pausiertes Telefon zwischen einem Laptop zu Hause und einem NAS im Büro. Beide Verbindungen sind als aus markiert." width="640" height="320"></picture>
</figure>

Den Hintergrunddienst anzuhalten stoppte früher die Synchronisierung und ließ den Rest des Geräts gesprächig. Der Empfänger, die LAN-Bake, das Rendezvous, das Relais und die Zuordnung am Router stoppen jetzt mit, und sie bleiben gestoppt, bis du fortsetzt. Eine Pause, die du selbst setzt, übersteht einen Neustart, und das zählt auf einem Telefon, das den Dienst den ganzen Tag stoppt und startet. Die kurze Pause, die `varsto disk` oder ein Import für sich selbst nimmt, wird nicht gespeichert. Die endet, wenn der Befehl endet.

Vorschaubilder in der Dateiliste erscheinen auf Telefonen wieder. Wenn der Motor beschäftigt war, antwortete der Dienst früher „kein Vorschaubild“, und die Seite glaubte es. Er antwortet jetzt „beschäftigt“, und die Seite versucht es erneut.

Die Standardregel nennt einen Ordner nicht mehr verletzt in einem Tresor, der keinen Plattenpool und keinen Verzeichnis-Speicher hat. Es gibt eine Warnung, dass nichts auf einer eigenen Platte liegt und wie du eine hinzufügst. Eine Regel, die du absichtlich setzt und die wirklich eine Kopie zu Hause verlangt, wird weiter daran gemessen. Dieselbe Unterscheidung gilt, wenn ein Import entscheidet, ob seine Quelle entfernt werden darf, sodass ein Ordner in diesem Tresor nicht mehr ewig auf eine Kopie auf einer Platte wartet, die du nicht hast.

Ein Befehl und der Hintergrunddienst nehmen dieselbe Sperre zum Holen, Freigeben, Schreiben und Verschieben einer Datei, sodass sie den Ordnerstand des anderen nicht mehr zurücknehmen. Ein Download oder ein Schreibvorgang, der scheitert, lässt keine Datei `.varsto-tmp-…` oder `.varsto-upload-…` mehr zurück, die einen Teil des Inhalts hält. Dateien, die von einem anderen Gerät ankommen, behalten die Änderungszeit, die ihr Schreiber festgehalten hat, statt mit dem Moment gestempelt zu werden, in dem sie heruntergeladen wurden. Werkzeuge, die dem Datum vertrauen, ein Build, eine Fotobibliothek, eine andere Sicherung, sehen nicht mehr jede geholte Datei als neu.

## Ein entferntes Gerät bleibt entfernt

Ordnerdatensätze, Gewährungen und die Hinterlegung eines entfernten Geräts zählen nur bis zur ersten Folgenummer, die es leer gelassen hat. Es kann nicht später zurückkommen und die Lücke mit einem rückdatierten Datensatz füllen. Ein Mitglied eines anderen Tresors wendet eine Entfernung an, die es aus der Ordnerepoche liest. Ein Ordner, dem der Entfernende keinen neuen Schlüssel geben konnte, bekommt ihn bei der nächsten Synchronisierung eines Eigentümers, der den Schlüssel noch hält. Was das entfernte Gerät schon auf der eigenen Platte hat, behält es. Das war immer so, und es ist immer noch so.

Das Beitreten liest das Manifest der Organisation und nimmt Tresorepochen und Widerrufe nur von ihren Administratoren. Ein Widerruf, den ein gewöhnliches Mitglied des Verzeichnisses geschrieben hat, öffnet den Tresor nicht mehr für ein Gerät, das beitritt.

Die Zeile „hält keinen Schlüssel“ im Aktivitätsprotokoll hat denselben Knopf wie die Ordnerzeile, sodass ein Telefon von dieser Zeile aus Zugriff verlangen kann, statt den Ordner zu suchen. Der restic-Spiegel und die Ordner, die darunter hängen, werden so angelegt, dass nur dieser Benutzer sie lesen kann.

## Der Name auf dem Symbol

Die Anwendungskennungen sind jetzt `net.varsto.app` auf Android und macOS, `net.varsto.app.ios` auf iOS und `net.varsto.app.alpha` für den unsignierten macOS-Build. Eine App, die schon installiert ist, behält ihre bisherige Kennung, und ihr Tresor wird nicht verschoben, bis du sie erneut installierst. Das neue Paket neben dem alten zu installieren ersetzt es nicht.

## Wenn du auf alpha.16 bist

Aktualisiere, wann du willst. Die beiden Versionen können einen Tresor teilen, während du das tust. Nichts in dieser Version verlangt, dass du zurücksetzt, einen neuen Satz druckst oder einen Android-Build deinstallierst, der schon der release-signierte aus alpha.16 ist. Wenn eine Freigabeanfrage oder eine Organisationsanfrage noch in einer Klartextdatei aus alpha.16 liegt, versiegelt sie der nächste Befehl, der sie liest. Das ist weiter eine Alpha.
