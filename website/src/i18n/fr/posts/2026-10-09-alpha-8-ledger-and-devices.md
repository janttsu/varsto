---
title: Alpha.8 : un registre qui reste petit, le retrait des appareils, et des téléphones qui ne gardent rien en clair
date: 2026-10-09
summary: Le registre ne liste plus que ce qui est nouveau, garde une vue en cache et s’élague derrière des points de contrôle signés ; les appareils peuvent être retirés, avec de nouvelles clés pour tout ce qui est écrit ensuite ; les téléphones gardent les dossiers chiffrés sous forme de blocs chiffrés ; et l’interface montre où sont vos données et comment circule le trafic pair à pair.
---
Alpha.8 est sorti d’une longue journée à utiliser alpha.7 sur un Mac, un bureau Linux et un téléphone Samsung, et à demander ce que devient la conception après quelques années d’usage.

## Un registre qui reste petit

Chaque appareil tient un journal signé et chiffré de faits : quel bloc il a stocké où, quelle copie il a vérifiée, quelle liste de fichiers il a publiée. Jusqu’ici chaque entrée restait pour toujours, comme son propre objet sur chaque stockage, et chaque synchronisation les listait toutes. Maintenant une synchronisation ne liste que ce qui est nouveau, l’appareil garde une vue chiffrée en cache au lieu de tout rejouer, une synchronisation écrit un seul lot, et chaque appareil écrit de temps en temps un point de contrôle signé. Une fois que tous vos appareils ont accusé réception d’un point de contrôle, les lots derrière lui sont supprimés, en gardant les derniers pour qu’un appareil restauré depuis une ancienne sauvegarde soit encore pris. Dans un coffre de test avec 20 000 lots, une synchronisation sans rien de nouveau est passée de 668 ms à 28 ms (à l’époque) et le registre sur le stockage de 171 Mo à 5 Mo. La page [Comment ça marche](../how-it-works/) explique le registre.

## Retirer un appareil

Un téléphone perdu ou un portable que vous n’utilisez plus peut être retiré depuis n’importe quel autre appareil (Réglages ou Pairs, « Retirer… », ou `varsto device revoke`). Ses entrées ultérieures sont ignorées, vos appareils refusent ses connexions, et le coffre passe à de nouvelles clés que seuls vos appareils restants reçoivent, de sorte que rien de ce qui est écrit ensuite ne s’ouvre avec ce que détient l’appareil retiré. Vous pouvez aussi lui ordonner de s’effacer la prochaine fois qu’il atteint un stockage. La liste des appareils montre le système, le modèle, la version de Varsto et la dernière synchronisation de chacun.

## Les téléphones gardent les dossiers chiffrés chiffrés

Un dossier gardé « chiffré sur ce téléphone » ne contient plus que des blocs chiffrés, les mêmes octets que ceux de vos stockages. La synchronisation sélective marche comme partout ailleurs ; les fichiers s’affichent dans la propre visionneuse de l’application, déchiffrés en mémoire, et ne sont remis à une autre application que lorsque vous le demandez, comme une copie temporaire qui est retirée quand le coffre se verrouille. Android peut envoyer les nouvelles photos et vidéos vers un dossier de votre choix.

## Voir ce qui se passe

- **Où sont vos données** : un schéma des dossiers vers les stockages et les appareils, avec le nombre de copies de chaque chose.
- **Trafic pair à pair** : quel appareil envoie quoi à quel autre, par quel chemin, à quelle vitesse.
- **Vérification automatique** : un autre appareil relit vos blocs selon un calendrier, de sorte qu’une politique comme « vérifié dans les 30 jours » reste vraie d’elle-même.
- Les boutons montrent tout de suite que quelque chose a commencé, et les téléchargements montrent leur progression.

## Et encore

Les dossiers Strongroom peuvent être convertis depuis des dossiers existants et reçoivent une clé de sécurité de secours ; les stockages peuvent être retirés une fois leurs blocs copiés là où il le faut ; les dossiers peuvent être détachés ou retirés du coffre, et les noms de premier niveau sont uniques ; les disques transporteurs peuvent recevoir un appareil de destination ; les prix des stockages alimentent les estimations de coût et la libération en un clic des fichiers inactifs ; l’assistant (MCP) ne peut jamais supprimer ni écraser des fichiers ; et sous Linux le premier démarrage installe Varsto pour votre utilisateur, avec un service en arrière-plan qui continue de synchroniser aussi pour ceux qui n’utilisent que la ligne de commande.

## Encore une alpha

La cryptographie n’a pas été auditée, le format peut encore changer, et un bogue peut détruire des données. Utilisez des données de test et conservez vos propres sauvegardes.
