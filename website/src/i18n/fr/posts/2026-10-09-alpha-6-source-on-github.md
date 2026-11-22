---
title: Alpha.6 : le code source est public, et chaque plateforme est construite dans le cloud
date: 2026-10-09
summary: Le dépôt est maintenant public sur GitHub sous la licence PolyForm Shield, les applications natives macOS et iOS se construisent sur GitHub Actions, Linux, Windows et Android se construisent sur des machines cloud de courte durée, et l’interface a été refaite autour d’une vue des fichiers.
---
Depuis alpha-0, les alphas ont ajouté l’essentiel de ce que le plan appelle le cœur : des stockages S3 et rclone, le partage avec un autre utilisateur par une clé scellée, des signatures et un échange de clés hybrides post-quantiques, des politiques de durabilité qui avertissent à temps, le transfert pair à pair entre vos propres appareils, la compression avant le chiffrement, des dossiers Strongroom derrière une clé de sécurité FIDO2, un kit de récupération imprimable, et un serveur MCP pour qu’un assistant puisse lire et réorganiser exactement les dossiers que vous lui accordez. Alpha.6 porte sur le projet autour de ce code.

## Le code source est public

Le dépôt est sur [github.com/janttsu/varsto](https://github.com/janttsu/varsto), sous la [PolyForm Shield License 1.0.0](../docs/licence.html) : à code source disponible, pas open source. Lisez-le, compilez-le, signalez ce qui casse dans le suivi des tickets. L’historique a été réécrit avant la publication pour qu’il ne porte ni chemins ni adresses personnels ; si vous avez cloné une copie privée plus ancienne, clonez de nouveau.

## Chaque plateforme est construite par une machine qui n’existait pas une heure plus tôt

- **macOS et iOS** se construisent sur GitHub Actions, sur des runners Apple Silicon : la suite de tests, le Varsto.app natif avec sa propre fenêtre, son élément dans la barre de menus et sa ligne de commande incluse, et l’enveloppe iOS pour le simulateur, qui y est lancée et photographiée. Une version étiquetée reçoit le zip macOS joint automatiquement.
- **Linux, Windows et Android** se construisent et se testent sur des machines cloud de courte durée, créées par un script, utilisées une fois et supprimées : la suite de tests complète sur un vrai Ubuntu, le zip Windows installé et mis à l’épreuve sur un vrai Windows Server, l’APK Android construit avec le SDK et le NDK puis lancé dans un émulateur.

Aucun build ne dépend plus de l’ordinateur d’un développeur, ce qui veut aussi dire que chaque paquet de la page de téléchargement vient d’un chemin documenté et reproductible.

## Une vue des fichiers d’abord

L’interface a été refaite : une barre latérale avec une arborescence de dossiers, une vue Fichiers avec un fil d’Ariane, des carrés d’état et un volet de détails, et un mode téléphone dans lequel les tableaux deviennent des cartes et la navigation passe en bas. Sur un téléphone, un dossier s’ajoute par son seul nom ; l’appareil choisit où il vit, donc vous ne tapez jamais un répertoire. Il y a aussi, dans les Réglages, un « recommencer sur cet appareil » protégé pour l’alpha, et la vue d’ensemble suggère où les fichiers inactifs coûteraient moins cher à conserver, d’après le propre relevé de dernière utilisation de Varsto et des données de prix ouvertes.

## Encore une alpha

Rien ici ne change l’avertissement de chaque page : la cryptographie n’a pas été auditée, le format peut encore changer, et un bogue peut détruire des données. Utilisez des données de test, conservez vos propres sauvegardes, et lisez le [modèle de défaillances](../docs/failure-model.html) avant de lui confier autre chose.
