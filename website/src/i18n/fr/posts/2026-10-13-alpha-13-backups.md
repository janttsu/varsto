---
title: Alpha.13 : des sauvegardes que rien ne peut changer
date: 2026-10-13
summary: Choisissez un dossier sur n’importe quel appareil et Varsto en garde des instantanés chiffrés, en lecture seule, sur vos stockages externes, jamais sur vos appareils, pendant autant de jours que vous voulez (90 par défaut). Les restaurations vont dans un répertoire que vous nommez, depuis l’application ou la ligne de commande.
---
La synchronisation garde chaque copie identique, ce qui est exactement ce que vous ne voulez pas quand un fichier est supprimé par erreur ou chiffré par un rançongiciel : le dégât atteint chaque appareil. Alpha.13 ajoute les sauvegardes, qui font l’inverse.

## Comment ça marche

Vous choisissez un dossier sur un appareil et vous donnez un nom à la sauvegarde. Varsto en prend un instantané : la liste des fichiers et chaque bloc, chiffrés comme tout le reste de ce qu’il stocke. Les instantanés ne vont que vers des stockages externes (buckets S3, destinations rclone, partages NAS, répertoires et stockage à froid), jamais vers des disques transporteurs et jamais vers vos autres appareils. Vos autres appareils voient que la sauvegarde existe et quels instantanés elle a, mais ils n’en téléchargent pas le contenu.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Les instantanés sont pris chaque jour par défaut, chaque semaine, ou seulement quand vous le demandez (`varsto backup take`). Les blocs qui n’ont pas changé ne sont stockés qu’une fois, quel que soit le nombre d’instantanés qui les utilisent.

## En lecture seule, et conservés pour une durée fixée

Un instantané n’est jamais modifié après avoir été pris. Sa date d’expiration est scellée dedans au moment de l’écriture, de sorte que changer la durée de conservation plus tard ne touche que les nouveaux instantanés. Une fois qu’un instantané a expiré, l’appareil qui a fait la sauvegarde le supprime des stockages. Seuls les blocs dont plus aucun instantané restant n’a besoin sont supprimés, et un jour de grâce laisse de la marge aux horloges un peu fausses. Si cet appareil a disparu, n’importe quel autre appareil du coffre le fait un peu plus tard. Arrêter une sauvegarde ne prend plus de nouveaux instantanés, mais ne supprime rien en avance.

## Restaurer

Une restauration va toujours dans un répertoire que vous nommez, et ce répertoire doit être vide sauf si vous autorisez l’écrasement. Vous pouvez choisir l’instantané le plus récent, un instantané numéroté, ou le plus récent à une date ou avant, et tout restaurer ou seulement certains chemins. L’application a une page Sauvegardes qui fait la même chose.

## Détails et limites

Le format est dans la section 31 de la [spécification](../docs/alpha-0-format.html). Dans cette première version, l’expiration suit l’horloge propre de chaque appareil, les politiques de durabilité ne couvrent pas encore les sauvegardes, et la vue des emplacements des données ne les montre pas.

Les versions plus anciennes ne comprennent pas les sauvegardes : mettez à jour chaque appareil d’un coffre vers alpha.13 avant d’en ajouter une.
