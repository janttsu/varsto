---
title: Alpha.12 : les petits fichiers dans des paquets, et Varsto en finnois et en suédois
date: 2026-10-12
summary: Les petits blocs chiffrés sont maintenant écrits dans des paquets, de sorte qu’un dossier de 20 000 petits fichiers devient 79 objets sur un bucket au lieu de 20 000. L’interface, la zone de notification, la barre de menus, les enveloppes mobiles et ce site sont disponibles en finnois et en suédois aussi bien qu’en anglais.
---
Alpha.12 a deux thèmes : moins d’objets sur votre stockage, et l’interface dans davantage de langues.

## Les petits blocs dans des paquets

Jusqu’ici chaque bloc chiffré était son propre objet sur le stockage. C’est simple et robuste, mais un dossier de nombreux petits fichiers, comme des notes, du code source ou les fichiers annexes d’une photothèque, devient des dizaines de milliers de tout petits objets. Beaucoup de fournisseurs facturent à la requête, certains à l’objet, et les lister et les contrôler tous est lent.

À partir de cette version, les blocs jusqu’à 128 Kio sont réunis dans des paquets d’environ 4 Mio ou de 256 membres. Un paquet est écrit avec un index qui nomme ses membres et l’endroit où chacun commence, et un membre se lit par une lecture par plage, de sorte que lire un petit fichier ne télécharge encore que ses propres octets. Les gros blocs sont toujours écrits un par un. Les paquets sont utilisés sur les buckets S3, les destinations rclone et les répertoires ; le stockage à froid, les pools de disques et les disques transporteurs gardent un objet par bloc.

Au laboratoire, un dossier de 20 000 petits fichiers est parti vers le bucket en 79 paquets au lieu de 20 000 objets. Chaque membre a été contrôlé par rapport à son nom après l’exécution.

Supprimer un bloc qui vit dans un paquet écrit un petit marqueur de suppression, et le paquet lui-même est supprimé une fois que chaque membre a disparu. La réparation, la vérification, les répliques, les déplacements de données et le retrait d’un stockage comprennent tous les paquets. Le format de stockage est décrit dans la section 30 de la [spécification du format](../docs/alpha-0-format.html).

Il n’y a pas de compatibilité avec les versions plus anciennes : un appareil en alpha.11 ou avant ne voit pas les blocs dans les paquets. Mettez à jour chaque appareil.

## Corrections trouvées en chemin

Les exécutions du labo ont trouvé des problèmes que les tests unitaires avaient manqués :

- `rclone serve s3` répond à une lecture par plage avec le statut 200 et seulement les octets demandés. Varsto accepte maintenant cela aussi bien que le 206 habituel, de sorte que les paquets se lisent correctement depuis de tels serveurs.
- Un appareil qui venait de lire les index des paquets ne regardait pas de nouveau les paquets qu’un autre appareil avait écrits quelques instants plus tard. Une lecture qui manque recharge maintenant les index tout de suite.
- Un appareil pouvait faire confiance à un index de paquet après qu’un autre appareil en avait supprimé des membres. Avant de décider qu’un bloc existe déjà et n’a pas besoin d’être écrit, Varsto contrôle maintenant qu’il est toujours dans son paquet.
- Les pools de disques et les autres stockages sans paquets écrivent de nouveau leurs blocs un à la fois, de sorte qu’un disque plein ou absent est signalé comme tel au lieu de faire échouer tout l’envoi.
- Un serveur S3 dont l’horloge a plus de quelques minutes de décalage est maintenant corrigé dans les deux sens, aussi lorsqu’il répond avec le statut 400 au lieu de 403.

## Finnois et suédois

L’interface de bureau, la zone de notification et la barre de menus macOS, les enveloppes Android et iOS, et ce site sont maintenant disponibles en finnois et en suédois. L’anglais reste la langue par défaut. La langue se choisit dans les réglages de l’interface ou en bas de la barre latérale, et la zone de notification et les applications suivent le même choix. La ligne de commande, la documentation et tout ce qui est dans le dépôt restent en anglais.

Les traductions des textes critiques pour la sécurité, comme ceux sur la suppression, le retrait des appareils et les mots de récupération, sont marquées pour relecture par des locuteurs natifs. Les corrections sont les bienvenues.

## Construire Varsto avec nous

La nouvelle page [Contribuer](../contribute/) décrit comment Varsto est construit et où l’aide est souhaitée : une relecture de la cryptographie et du format de stockage, Windows, iOS et Android, la traversée du NAT sur d’autres réseaux que ceux du mainteneur, davantage de fournisseurs S3, le packaging et les traductions.
