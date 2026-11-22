---
title: Alpha.16 : format de stockage 3, accès aux dossiers sur approbation, et un service de rendez-vous
date: 2026-11-04
summary: Un nouveau format de stockage avec un registre au niveau des paquets, des enregistrements signés et des mots de récupération, de sorte que les coffres existants doivent être recréés ; les dossiers s’ouvrent à un appareil sur l’approbation d’un propriétaire ; les appareils se trouvent par un service de rendez-vous facultatif ; rejoindre et changer les membres fonctionne hors ligne ; et des imports depuis des torrents et YouTube.
---
La version actuelle est [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Cette note décrit une version plus ancienne. Les [téléchargements](https://varsto.net/downloads/) servent alpha.17, et le code source est sur [GitHub](https://github.com/janttsu/varsto).

Alpha.16 change de nouveau le format de stockage. C’est la chose principale à savoir avant de mettre à jour : les coffres faits par alpha.15 ou plus ancien ne peuvent pas être ouverts par cette version et doivent être recréés. Le reste de la version est une longue liste de changements dans la façon dont les appareils rejoignent, se trouvent et supportent un mauvais réseau, une nouvelle page Import, et un grand ensemble de corrections et de durcissement issus d’une relecture du nouveau format.

## Recréer un coffre

Il n’y a pas de migration. Alpha.16 refuse un coffre plus ancien quand il l’ouvre ou quand un appareil rejoint par son stockage, et le message dit quoi faire. Alpha.15 refuse un coffre au format 3 de la même façon, donc les deux versions ne peuvent pas partager un coffre dans un sens ni dans l’autre. Chaque appareil d’un coffre doit exécuter alpha.16. Gardez vos fichiers où ils sont, puis :

1. Gardez le binaire alpha.15 à portée de main si vous pouvez avoir besoin de lire l’ancien coffre.
2. `varsto reset --yes` sur l’appareil, puis `varsto init`. Il imprime un kit avec deux jeux de mots : les mots du coffre et, nouveaux dans le format 3, les mots de récupération. Conservez les deux.
3. Ajoutez de nouveau les stockages, ajoutez les dossiers (les mots de récupération sont demandés ici) et synchronisez.

## Android : désinstallez d’abord l’ancien APK

Le paquetage Android est maintenant un APK signé pour la publication (`varsto-<version>-android.apk`), et non un build de débogage, de sorte qu’une version ultérieure s’installe par-dessus comme une mise à jour. Il est signé avec une nouvelle clé. Une installation d’un APK de débogage plus ancien (alpha.15, ou une version quotidienne plus ancienne) ne peut pas être mise à jour vers celui-ci : Android refuse la mise à jour. Désinstallez d’abord l’ancienne application, puis installez la nouvelle. Désinstaller retire la copie du coffre de cet appareil, donc assurez-vous que le coffre a un autre appareil ou un stockage avant de le faire. Le téléchargement Android quotidien reste un build de débogage sous le nom `varsto-daily-android-debug.apk`.

## Format de stockage 3

Le format 3 est décrit dans la section 77 de la spécification et dans le document de conception du format 3. Ce qu’il change pour un utilisateur :

- Le registre ne liste plus chaque bloc. Il déclare des paquets de quelques tailles fixes (256 Kio à 64 Mio, complétés), de sorte qu’un stockage voit des classes de taille et non combien il y a de blocs ou de fichiers.
- Chaque objet publié autre qu’un paquet est un enregistrement signé qui nomme la clé sous laquelle il est scellé. Les manifestes, les listes de la corbeille et les instantanés sont une base plus de petits deltas, et chaque dossier garde une carte de blocs signée par appareil écrivant.
- Une clé de dossier n’atteint un appareil que sous forme de concession qu’un propriétaire a approuvée. Un appareil qui rejoint avec les mots du coffre voit les noms des dossiers et ne détient aucun contenu ; il demande avec `varsto folder request`, un propriétaire compare six mots affichés sur les deux appareils et approuve avec `varsto folder approve` (aussi `requests`, `deny`, `members`, `role`). Le service en arrière-plan n’approuve jamais. L’interface a une carte Accès au dossier sur la page Fichiers.
- Chaque époque de clé de dossier a une copie de séquestre sous les mots de récupération. `varsto folder add` la crée, `varsto recovery escrow` en écrit une manquante plus tard, et `varsto status` avertit jusque-là. `varsto join --recovery-words` ouvre chaque dossier qui a une copie de séquestre.
- Les pairs ne parlent qu’en TLS, avec des jetons liés à la connexion, et comparent les têtes de registre, de sorte qu’un stockage qui retient des lots ou les ramène en arrière est remarqué, et la page Aide et une notification le disent.
- Retirer un appareil tient maintenant : un appareil révoqué ne reçoit pas la clé de dossier suivante, et ses enregistrements cessent de compter au retrait.

## Se trouver : le service de rendez-vous

Les appareils peuvent se trouver à travers les réseaux par un service de rendez-vous facultatif, par défaut `https://varsto.net/rv`. Un appareil y laisse son enregistrement de pair scellé, lit les enregistrements du coffre, apprend sa propre adresse publique et, quand aucune adresse ne répond, atteint un pair par un perçage coordonné ou, en dernier recours, un relais chiffré de bout en bout (affiché comme `relayed via rendezvous`). Un appareil qui rejoint et ne trouve rien sur son réseau peut retrouver une offre par code ou par lien et s’appairer à travers le relais. Le service voit des étiquettes, des adresses IP et des nombres d’octets, jamais l’identité du coffre ni le contenu. `varsto p2p rendezvous set <url> | on | --off | status` ou la page Pairs le change, et le serveur peut être auto-hébergé (`varsto-rendezvous`, un binaire Linux statique dans le build quotidien ; le port UDP par défaut est 3334). Tout fonctionne aussi sans lui.

## Un mauvais réseau, et travailler hors ligne

- Un stockage qui ne peut pas être atteint ne fait plus échouer toute une synchronisation. Il est marqué hors service pour cette exécution et se repose entre les exécutions, et les autres stockages continuent ; ce qu’il a manqué y est copié plus tard.
- Les appels S3 et rclone ont des délais adaptés à la taille du transfert, des nouvelles tentatives, et des envois en plusieurs parties qui peuvent reprendre, de sorte qu’une liaison lente coûte des secondes, pas des minutes.
- Le pair à pair fonctionne sans aucun stockage, depuis un répertoire de pairs enregistré, de sorte que la synchronisation sur le réseau local fonctionne sans internet.
- Rejoindre par appairage n’a plus besoin qu’un stockage réponde, et les changements d’appartenance (ajouter un dossier, approuver, changer un rôle, partager) sont gardés d’abord sur l’appareil et envoyés quand un stockage répond. `varsto status` dit « N changements en attente d’envoi ».
- Les actions locales (imports, la page Corbeille, les vignettes, les écritures de fichiers) finissent pendant qu’un stockage est hors service et signalent « envoi en attente ».
- L’interface, la zone de notification, la ligne de commande et MCP ne se figent plus pendant qu’une synchronisation attend sur une liaison morte.

## Imports

- Une seule page Import pour chaque source (un dossier ou un disque, un dépôt git-annex, un lecteur cloud via rclone, un torrent, YouTube), avec une liste des imports en cours.
- `varsto import torrent` importe les torrents plus gros que le disque par lots qui gardent une réserve d’espace libre ; un fichier ne quitte le disque de téléchargement qu’une fois ses blocs sur un stockage et la politique du dossier respectée.
- `varsto import youtube` archive des chaînes, des listes de lecture et des vidéos dans des dossiers avec yt-dlp, avec des réglages courtois par défaut et une réserve d’espace libre.

## Disques et serveurs

- `varsto mailbox` met en attente des blocs depuis un disque branché pour un disque de pool ou un stockage qui est absent, dans une boîte d’envoi durable et contrôlée par empreinte, de sorte qu’un bloc qui n’est que sur le disque A atteint le disque B quand B est branché.
- `varsto service remember` fonctionne sans session de bureau (en SSH, sur des serveurs) par `systemd-creds` ou le trousseau du noyau ; `varsto service forget` le retire.
- `varsto service stop` reste maintenant arrêté, et une mise à jour de soi-même redémarre encore le service.

## Corrections et durcissement

- Une récupération n’écrase plus un fichier modifié après le parcours, et un fichier mauvais n’arrête plus la récupération ni l’envoi d’un dossier. Un fichier ou un répertoire illisible est compté au lieu de faire paraître supprimés les fichiers en dessous.
- Appartenance : le retrait d’un appareil vaut pour ceux qui rejoignent ensuite et pour les dossiers qui n’ont pas reçu de nouvelle clé, et seules l’époque, la révocation ou l’effacement d’un administrateur sont adoptés.
- Le vidage, le retrait d’un stockage et le rangement après l’insertion d’un disque conservent tout paquet qui pourrait être la seule copie. La réparation, l’envoi après un lot manquant et l’attachement après un détachement sont corrigés.
- Les lectures par plage S3 ne font plus dire à `fsck` que chaque paquet est trop court.
- La visualisation montre une note de chargement ou une note de coffre vide au lieu de la scène d’exemple, et les vignettes s’affichent dans la page.
- Les poignées de main TLS ont un délai qui est respecté, et une adresse peut en tenir au plus 64 inachevées. Un client local bloqué ne peut plus geler l’API locale. Le serveur de rendez-vous a une limite de débit par classe de requête et une mémoire bornée pour les recherches. Les avis de dépendances signalés par `cargo audit` sont corrigés.
- Les workflows GitHub s’exécutent avec des droits en lecture seule, sauf là où ils publient.

## Compatibilité

Chaque appareil d’un coffre doit exécuter alpha.16. Alpha.15 ne peut pas lire un coffre alpha.16 et alpha.16 ne peut pas lire un coffre alpha.15. Mettez à jour tous les appareils ensemble et recréez le coffre comme décrit plus haut. C’est encore une alpha : pas pour des données de production. La liste complète est dans le journal des changements.
