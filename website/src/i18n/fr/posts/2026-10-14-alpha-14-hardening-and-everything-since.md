---
title: Alpha.14 : une relecture de sécurité, ses corrections, et tout ce qui a été fusionné depuis alpha.13
date: 2026-10-14
summary: Une relecture de sécurité au niveau du code de tout le programme, les corrections qu’elle a demandées, une synchronisation bien plus rapide, des déplacements reprenables vers une pile de disques amovibles, et la vingtaine de fonctionnalités qui attendaient sur la branche principale depuis alpha.13.
---
La version actuelle est [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Cette note décrit une version plus ancienne. Les [téléchargements](https://varsto.net/downloads/) servent alpha.17, et le code source est sur [GitHub](https://github.com/janttsu/varsto).

Alpha.14 est la plus grande version jusqu’ici. Elle porte deux choses : l’arriéré de fonctionnalités arrivées sur la branche principale après alpha.13, et la première série de corrections d’une relecture de sécurité qui a lu chaque ligne du programme avec en tête un stockage hostile, un réseau hostile et un appareil compagnon hostile.

## La relecture de sécurité

La relecture a trouvé les primitives cryptographiques solides, et l’autorisation autour d’elles insuffisante. Alpha.14 ferme les parties qui pouvaient l’être sans changer le format de stockage :

- Les événements du registre sont acceptés selon le rôle : une réplique ne peut déclarer que des copies, un membre d’un dossier partagé ne peut parler que de ce dossier, et les points de contrôle ne sont pris que des appareils complets. Un stockage qui retient un lot est remarqué, un objet de rebut sous le propre nom d’un appareil ne met plus l’appareil sous clôture, et une révocation ne compte qu’avec son époque de clé signée.
- Le service et le transport entre pairs : le canal latéral STUN est borné, le navigateur reçoit un code de démarrage à usage unique à la place du jeton de session, une requête forgée ne peut plus faire planter l’API, les clés Strongroom doivent correspondre à un engagement et la clé de sécurité demande son code PIN, les secrets ont disparu de la ligne de commande, le programme de mise à jour refuse les listes signées périmées, et les lectures sur les stockages sont bornées.
- Hygiène : les fichiers de clés sont créés privés dès le premier octet, les jetons sont comparés en temps constant, le matériel de clé est effacé de la mémoire, les parts de récupération portent un contrôle, et la bibliothèque Shamir a été remplacée par une branche corrigée.

Deux constats demandent un nouveau format de stockage et ne sont pas dans cette version : les listes de fichiers et les époques de partage sont encore acceptées sur la seule clé du dossier, et le nonce du morceau vient encore du texte en clair. Les deux sont construits sur les branches du format 2, qui est la version suivante. D’ici là, traitez les dossiers partagés et les répliques non fiables comme la relecture le décrit : un détenteur de la clé d’un dossier peut encore changer ce que ce dossier montre.

## Plus rapide

Synchroniser 50 000 petits fichiers vers un stockage local est passé de 167 secondes à 21 ; 10 000 fichiers, de 77 à 8,5. L’horloge n’est plus écrite sur le disque pour chaque fichier, les stockages sont ouverts une fois par synchronisation, les envois se répartissent par stockage, le client S3 sonde une seule fois si les écritures conditionnelles sont honorées, et les binaires sont construits avec l’optimisation à l’édition de liens et un allocateur plus rapide.

## Tout depuis alpha.13

L’activité en direct entre appareils, le contrôle de pourriture binaire, les disques entiers pour les pools de disques, les sauvegardes avec restic, les analyses de fichiers et `varsto search`, les clés MCP à portée limitée, la reconstruction du registre, la vérification selon le support, la comptabilité des disques et « le prochain disque à brancher », le guide du kit de récupération, les imports depuis git-annex, les lecteurs cloud et les dossiers locaux, la corbeille du coffre, les quotas de stockage et le vidage, les journaux de débogage locaux, les noms d’origine, la sécurité des dossiers (marqueur, garde contre les suppressions en masse, envoi seul et réception seule), les règles d’ignorance, les métadonnées de fichiers, l’historique des versions, les invitations par code QR, la redirection de ports du routeur, l’espace disque libre minimum, le flux d’événements, les membres en lecture seule, les règles par plateforme, l’historique des changements, et les déplacements reprenables d’un dossier vers une pile de disques amovibles, un disque à la fois.

## Compatibilité

Le format de stockage n’a pas changé, mais chaque appareil d’un coffre doit exécuter alpha.14 : le cache de la vue du registre et les contrôles des enregistrements ont changé, et les appareils plus anciens ne liront pas ce qu’alpha.14 écrit. La fonction de téléchargement de torrents sur la branche principale ne fait pas partie de cette version.
