---
title: Alpha.13: Sicherungen, die nichts ändern kann
date: 2026-10-13
summary: Wähle einen Ordner auf einem beliebigen Gerät, und Varsto behält verschlüsselte, schreibgeschützte Schnappschüsse davon auf deinen externen Speichern, nie auf deinen Geräten, so viele Tage, wie du wählst (standardmäßig 90). Wiederherstellungen gehen in ein Verzeichnis, das du nennst, aus der App oder von der Kommandozeile.
---
Synchronisierung hält jede Kopie gleich, und genau das willst du nicht, wenn eine Datei aus Versehen gelöscht oder von Ransomware verschlüsselt wird: der Schaden erreicht jedes Gerät. Alpha.13 fügt Sicherungen hinzu, die andersherum funktionieren.

## So funktioniert es

Du wählst einen Ordner auf einem Gerät und gibst der Sicherung einen Namen. Varsto nimmt einen Schnappschuss davon: die Dateiliste und jeden Block, verschlüsselt wie alles andere, das es speichert. Schnappschüsse gehen nur auf externe Speicher (S3-Buckets, rclone-Remotes, NAS-Freigaben, Verzeichnisse und Kaltspeicher), nie auf Überträger-Platten und nie auf deine anderen Geräte. Deine anderen Geräte sehen, dass die Sicherung existiert und welche Schnappschüsse sie hat, aber sie laden ihren Inhalt nicht herunter.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Schnappschüsse werden standardmäßig täglich genommen, wöchentlich oder nur wenn du sie verlangst (`varsto backup take`). Blöcke, die sich nicht geändert haben, werden einmal gespeichert, egal wie viele Schnappschüsse sie nutzen.

## Schreibgeschützt und für eine gesetzte Zeit behalten

Ein Schnappschuss wird nach dem Aufnehmen nie geändert. Sein Ablaufdatum wird beim Schreiben in ihm versiegelt, sodass eine spätere Änderung der Aufbewahrung nur neue Schnappschüsse betrifft. Sobald ein Schnappschuss abgelaufen ist, löscht das Gerät, das die Sicherung gemacht hat, ihn von den Speichern. Gelöscht werden nur Blöcke, die kein verbleibender Schnappschuss braucht, und ein Tag Schonfrist lässt Uhren zu, die ein wenig danebenliegen. Wenn dieses Gerät weg ist, tut es ein beliebiges anderes Gerät des Tresors etwas später. Eine Sicherung zu stoppen nimmt keine neuen Schnappschüsse, löscht aber nichts vorzeitig.

## Wiederherstellen

Eine Wiederherstellung geht immer in ein Verzeichnis, das du nennst, und dieses Verzeichnis muss leer sein, außer du erlaubst das Überschreiben. Du kannst den neuesten Schnappschuss wählen, einen nummerierten oder den neuesten an oder vor einem Datum, und alles wiederherstellen oder nur einige Pfade. Die App hat eine Seite Sicherungen, die dasselbe tut.

## Einzelheiten und Grenzen

Das Format steht in Abschnitt 31 der [Spezifikation](../docs/alpha-0-format.html). In dieser ersten Version folgt das Ablaufen der eigenen Uhr jedes Geräts, Aufbewahrungsregeln decken Sicherungen noch nicht ab, und die Ansicht der Datenorte zeigt sie nicht.

Ältere Versionen verstehen Sicherungen nicht: aktualisiere jedes Gerät eines Tresors auf alpha.13, bevor du eine hinzufügst.
