---
title: Alpha.7 : appairer les appareils avec un code, actions du Finder, et un vrai chemin à travers le NAT
date: 2026-10-09
summary: Les appareils s’appairent maintenant depuis l’interface avec un code à usage unique, le Finder peut télécharger un fichier substitut ou libérer de la place d’un clic droit, l’application macOS s’installe depuis une image disque, les appareils s’atteignent à travers le NAT, et les disques amovibles peuvent former un pool.
---
Alpha.7 est surtout le résultat d’une journée d’usage de l’alpha sur de vrais appareils : un téléphone Samsung, un Mac et un bucket de test. Chaque section ci-dessous a commencé par quelque chose qui ne marchait pas comme il fallait.

## Appairer un appareil avec un code

Ajouter un appareil voulait dire copier une clé de coffre de 64 caractères et taper les réglages d’un stockage que les deux appareils peuvent atteindre. Maintenant, l’appareil qui a déjà le coffre affiche **Ajouter un appareil** sous Appareils : un code de neuf chiffres qui ne sert qu’une fois, pendant dix minutes. Sur le nouvel appareil, vous choisissez **Appairer avec votre autre appareil**, vous tapez le code, un nom et une phrase secrète, et c’est tout.

Les deux appareils se trouvent sur le réseau local, exécutent SPAKE2 avec le code comme secret (une mauvaise supposition ne peut pas être vérifiée hors ligne, et trois mauvais codes ferment l’offre), confirment la clé dans les deux sens, et alors seulement la clé du coffre voyage, avec les réglages des stockages et leurs secrets, scellée sous la clé partagée. Le nouvel appareil rejoint par le premier stockage qu’il peut atteindre. S’il n’est pas trouvé sur le réseau, l’adresse affichée sous le code fonctionne aussi. Le même parcours existe en ligne de commande : `varsto pair offer` et `varsto pair join`.

## Le Finder connaît les fichiers substituts

Sous macOS, un clic droit sur les fichiers propose **Télécharger avec Varsto** ou **Libérer de l’espace avec Varsto**, et un double-clic sur un fichier substitut télécharge le fichier et l’ouvre. Libérer de la place est refusé tant que chaque bloc n’est pas sur un stockage *et* que le fichier sur le disque n’est pas la version qui a été synchronisée ; avant cette version, un fichier modifié après la dernière synchronisation aurait pu être remplacé par son fichier substitut. Le téléchargement macOS est maintenant une image disque : ouvrez-la et faites glisser Varsto vers Applications.

## Les appareils s’atteignent à travers le NAT

Le transfert pair à pair ne marchait que sur le réseau local et à travers des ports redirigés. Maintenant, les appareils apprennent leur adresse publique avec STUN, percent le NAT en QUIC avec un certificat épinglé par appareil, et se rabattent sur un relais par l’un de vos propres appareils joignables. Cela a été testé entre un réseau domestique et une machine cloud derrière son propre NAT, dans les deux sens, et avec l’UDP bloqué pour forcer le relais.

## Pools de disques amovibles

Un stockage peut être un pool de disques amovibles : Varsto les remplit selon l’espace libre, avec une réserve, sait quel disque détient quel bloc, vous demande de brancher un disque précis quand il en a besoin, et compte un disque hors ligne comme une copie en date de son dernier contrôle.

## Plus petites choses

- Les politiques de durabilité s’éditent pour chaque dossier dans un seul tableau sur le bureau, et la règle complète et ses raisons sont visibles.
- Sur un téléphone, vous pouvez ajouter des fichiers et des sous-dossiers, ouvrir un fichier dans une autre application ou le partager, et garder un dossier comme fichiers en clair dans le stockage interne au lieu de chiffrés.
- Les détails d’un fichier disent si cet appareil a le fichier et quels stockages le détiennent.
- La fenêtre suit une pause ou une synchronisation lancée depuis la barre de menus.
- Rejoindre accepte les 24 mots de récupération aussi bien que la clé hexadécimale.

## Encore une alpha

L’avertissement de chaque page tient toujours : la cryptographie n’a pas été auditée, le format peut encore changer, et un bogue peut détruire des données. Utilisez des données de test et conservez vos propres sauvegardes.
