---
title: Alpha.15 : format de stockage 2, un programme d’installation Windows et un canal quotidien
date: 2026-10-16
summary: Un nouveau format de stockage qui corrige deux constats de la relecture de sécurité, de sorte que les coffres existants doivent être recréés ; Windows reçoit un programme d’installation, une fenêtre native et des mises à jour automatiques ; et un canal de versions quotidiennes signé.
---
La version actuelle est [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Cette note décrit une version plus ancienne. Les [téléchargements](https://varsto.net/downloads/) servent alpha.17, et le code source est sur [GitHub](https://github.com/janttsu/varsto).

Alpha.15 change le format de stockage. C’est la chose principale à savoir avant de mettre à jour : les coffres faits par alpha.14 ou plus ancien ne peuvent pas être ouverts par cette version et doivent être recréés. Le reste de la version est une longue liste de corrections et de travail sur l’interface, une vraie installation Windows, et un canal de versions quotidiennes pour ceux qui veulent tester le code le plus récent.

## Le format 2 et ce qu’il veut dire

La relecture de sécurité derrière alpha.14 a trouvé deux problèmes dans la façon dont les blocs étaient stockés, qui ne pouvaient pas être corrigés sans changer le format. Le format 2 les corrige :

- Le nonce d’un bloc chiffré est maintenant dérivé des octets exacts qui sont chiffrés (après compression), et non du texte en clair. Avant, le nonce dépendait d’un résultat de compression qui n’était pas garanti identique d’une version de zstd à l’autre.
- Le découpeur est à clé par dossier. Les points de coupe étaient une fonction publique du contenu du fichier, de sorte qu’un stockage qui connaissait un fichier pouvait le reconnaître aux tailles de ses blocs. Maintenant, le même fichier dans deux dossiers est coupé à des endroits différents.
- Chaque bloc est stocké dans un paquet (64 Mio, 256 Mio sur les stockages à froid) et aucun bloc n’est un objet à lui seul, de sorte qu’un stockage voit les tailles des paquets et non les tailles ni le nombre de blocs dedans. Les paquets ont des index chiffrés, et les blocs supprimés sont suivis par dossier, puis retirés quand le paquet est réécrit.
- La compression est zstd au niveau 3 après une sonde rapide : le texte se compresse presque aussi bien qu’avant et s’écrit plusieurs fois plus vite.

Ce que le format 2 ne corrige pas : les listes de fichiers et les époques de partage sont encore acceptées sur la seule clé du dossier, parce que fermer cela demande des manifestes signés et des époques de partage, qui appartiennent à la couche des enregistrements du format suivant. Tant que cela n’existe pas, un détenteur de la clé d’un dossier peut encore changer ce que ce dossier montre, et les répliques non fiables et les dossiers partagés doivent être traités ainsi. Les deux constats critiques restent ouverts dans alpha.15.

**Recréer un coffre.** Il n’y a pas de migration. Alpha.15 refuse un coffre plus ancien quand il l’ouvre ou quand un appareil rejoint par son stockage, et le message dit quoi faire. Gardez vos fichiers où ils sont, puis :

1. Gardez le binaire alpha.14 à portée de main si vous pouvez avoir besoin de lire l’ancien coffre.
2. `varsto reset --yes` sur l’appareil, puis `varsto init`.
3. Ajoutez de nouveau les stockages et synchronisez les dossiers.

Alpha.14 refuse un coffre au format 2 de la même façon, donc les deux versions ne peuvent pas partager un coffre dans un sens ni dans l’autre.

## Windows : le programme d’installation, une fenêtre native et les mises à jour automatiques

Le zip portable n’existe plus. Windows n’a plus qu’un téléchargement, `Varsto-<version>-setup.exe` : il met à niveau sur place, peut réparer une installation, et son programme de désinstallation conserve votre dossier de données. L’interface s’ouvre dans une fenêtre native (WebView2) dont la taille et la position sont mémorisées, une fenêtre par utilisateur, et la zone de notification la lance. Les copies installées par le programme d’installation cherchent des mises à jour une fois par jour, vérifient le programme d’installation signé et l’installent en silence. Si vous exécutez encore une copie portable décompressée, `varsto update` vous dit de lancer le programme d’installation une fois ; les mises à jour continuent seules ensuite.

## Tout le reste depuis alpha.14

- Une vue d’ensemble des dossiers avec un indicateur de sécurité par dossier : 100 % dans un stockage externe, 100 % sur vos propres disques seulement, partiellement protégé, ou seulement sur les appareils.
- Une visualisation en direct des appareils, des stockages, des disques et du cloud, avec des flux animés, et un vrai plein écran dans le navigateur et dans les enveloppes Android, macOS et Windows (Échap en sort).
- Acheminement : un appareil attaché à un dossier, même en synchronisation sélective, peut porter les blocs d’autres appareils vers les stockages où il peut écrire, de sorte que les photos d’un téléphone atteignent un bucket pour lequel seul le portable a les identifiants. Le dialogue d’attachement demande maintenant la synchronisation complète ou sélective, et le sens.
- L’appairage propose chaque adresse locale utilisable, la meilleure d’abord, et rejoindre se rabat de l’une à l’autre et sur une recherche du réseau local, avec une progression visible et une erreur qui nomme ce qui a été essayé.
- Les données nouvelles ont un délai de grâce avant que la vérification signale une infraction : les blocs stockés dans le plus grand de la fenêtre de vérification et de 24 heures s’affichent comme « vérification en attente ».
- L’interface reste utilisable pendant les longues synchronisations : les lectures sont répondues depuis la dernière réponse conservée quand le service est occupé, les listes se dessinent au fur et à mesure, et la page n’est jamais rechargée.
- Corrections : le vidage et l’emplacement refusent maintenant les choix contradictoires, les vignettes pour les stockages ajoutés plus tard, les téléphones n’acceptent que les stockages S3 et rclone, les photos et vidéos déjà sur un téléphone sont sauvegardées de la plus récente à la plus ancienne, l’impression du kit de récupération, l’icône du Dock macOS, le bouton Retour et le clavier d’Android, `reset` et les redémarrages du service, et l’initialisation d’un disque avec une disposition GPT moderne.
- Un `.ipa` iOS non signé pour AltStore, SideStore et Sideloadly.
- Le site a une traduction française, et les pages finnoises et suédoises montrent des captures d’écran de l’interface dans leur propre langue.

## Le canal quotidien

`varsto update --daily` installe la dernière version quotidienne de la ligne principale. Les versions quotidiennes sont faites pour toutes les plateformes chaque fois que la branche principale bouge, et elles sont publiées sur varsto.net/daily/. La liste des sommes de contrôle est signée avec une clé quotidienne distincte de la clé de version : le programme de mise à jour ne fait confiance à chaque clé que pour son propre canal, de sorte qu’une signature quotidienne ne valide jamais une version officielle, et inversement. Il refuse aussi les listes périmées, datées dans le futur, ou plus anciennes que le build que vous exécutez. La mise à jour en arrière-plan et l’interface restent sur les versions officielles ; le canal quotidien n’est jamais lancé qu’à la main.

Les versions quotidiennes sont des versions de développement. Elles ne sont pas pour des données de production, et une version quotidienne peut porter un changement de format de stockage avant toute version officielle.

## Compatibilité

Chaque appareil d’un coffre doit exécuter alpha.15. Alpha.14 ne peut pas lire un coffre alpha.15 et alpha.15 ne peut pas lire un coffre alpha.14, et aucune des deux ne lit les paquets ni les listes de marques de suppression de l’autre. Mettez à jour tous les appareils ensemble et recréez le coffre comme décrit plus haut.
