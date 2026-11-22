---
title: Alpha.9 : les données où vous les voulez, la réparation toute seule, des mises à jour signées, et chaque plateforme construite au grand jour
date: 2026-10-10
summary: Les dossiers peuvent être placés sur des stockages choisis et déplacés de l’un à l’autre, les copies perdues sont réparées automatiquement, les mises à jour sont signées avec une clé hors ligne, les téléchargements pair à pair récupèrent plusieurs blocs à la fois, et chaque paquet est maintenant construit, testé et photographié sur les runners de GitHub.
---
Alpha.9 (un build qui n’a jamais été étiqueté seul ; ses changements ont été livrés dans alpha.10) porte sur la durée : décider où vivent les données, les ramener au nombre de copies que votre politique demande, sans avoir à vous le dire, et faire confiance à la mise à jour qui apporte la version suivante.

## Les données où vous les voulez

Chaque dossier peut maintenant avoir un emplacement : les stockages où vont ses blocs. Les données peuvent être déplacées d’un stockage à un autre (un dossier entier, ou seulement les fichiers inactifs depuis un certain nombre de jours), bloc par bloc, chaque bloc étant écrit puis relu sur le nouveau stockage avant que l’ancienne copie soit supprimée, et un déplacement interrompu reprend simplement quand vous le relancez. Un pool de disques amovibles peut demander des copies sur des disques gardés en des lieux différents, par exemple un à la maison et un au travail, et Varsto remplit chaque disque de ce qui manque encore à son lieu.

## La réparation toute seule

Quand une copie disparaît, qu’un stockage est retiré ou qu’une vérification échoue, l’appareil qui détient les données remet le bloc là où la politique et l’emplacement du dossier le veulent, depuis ses propres fichiers, le cache de blocs chiffrés, un autre stockage ou un pair. La file de réparation est visible dans l’interface et avec `varsto repair`.

## Mises à jour signées

La liste des sommes de contrôle de chaque version est maintenant signée avec la clé de version du projet, qui ne quitte jamais la machine du mainteneur, et le programme de mise à jour refuse une version qui n’est pas signée avec elle. Il compare aussi la somme de contrôle avec celle jointe à la version GitHub, un second canal. `varsto verify-release` contrôle un téléchargement à la main, et `minisign` aussi. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) explique le dispositif.

## Pair à pair plus rapide

Les téléchargements gardent jusqu’à huit blocs en vol (à l’époque), récupèrent à l’avance les petits fichiers d’un dossier et partagent une connexion par pair ; un appareil qui sert des blocs ne lance plus une synchronisation complète pour lui-même toutes les quelques secondes. Les [mesures](../benchmarks/) comparent Paris, Amsterdam et Varsovie, le pair à pair contre un bucket S3.

## Construit au grand jour

Chaque plateforme est maintenant construite et testée sur les runners de GitHub à chaque changement : les paquets Linux et Windows (celui de Windows testé sur Windows Server 2025, y compris les entrées du menu de l’Explorateur), l’application Android dans l’émulateur, l’image disque macOS et l’application iOS sur Apple Silicon. Les mêmes exécutions prennent les [captures d’écran](../screenshots/), de sorte que les images de ce site suivent le build le plus récent.

## Et encore

Le partage enregistre qui a demandé l’accès, par empreinte ; retirer un membre fait passer le partage à de nouvelles clés ; et un Strongroom peut recevoir une nouvelle clé. Les fichiers peuvent être téléchargés ou libérés depuis le gestionnaire de fichiers sous Linux (Nautilus, Dolphin, Nemo) et sous Windows (Explorateur). Les lignes de dossiers gardent leurs deux boutons principaux et mettent le reste dans un menu. L’application macOS et les applications de téléphone disent quand une version plus récente attend sur la page de téléchargement, au lieu de se déclarer à jour. Et les gros lots du registre n’échouent plus sur S3.

## Mettez à jour chaque appareil avant de déplacer des données

Déplacer des données écrit une nouvelle sorte d’entrée de registre qu’alpha.8 et les versions précédentes ne peuvent pas lire : leurs synchronisations échoueraient dès le premier déplacement. Mettez d’abord à jour tous vos appareils. À partir de cette version, les entrées inconnues sont sautées, de sorte que les ajouts ultérieurs ne la casseront pas. Les clients jusqu’à alpha.8 ne contrôlent que la somme de contrôle lorsqu’ils se mettent à jour ; cette version est la première dont le programme de mise à jour exige la signature.

## Encore une alpha

La cryptographie n’a pas été auditée, le format peut encore changer, et un bogue peut détruire des données. Utilisez des données de test et conservez vos propres sauvegardes.
