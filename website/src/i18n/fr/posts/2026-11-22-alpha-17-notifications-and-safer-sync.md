---
title: Alpha.17 : le coffre reste, les erreurs silencieuses s’en vont
date: 2026-11-22
summary: Pas de nouveau format de stockage et pas de nouveaux mots à noter. Alpha.17 est la version qui empêche une synchronisation ratée de supprimer des fichiers, conserve la dernière sauvegarde, et prévient votre téléphone quand quelque chose ne va vraiment pas.
---
Vous pouvez mettre à jour celle-ci sans cérémonie. Alpha.17 ouvre un coffre alpha.16 tel quel. Il n’y a pas de nouveau format, pas de second jeu de mots, et rien à recréer. Ce qui change, c’est le genre d’erreur qui arrivait pendant que vous regardiez ailleurs.

Une récupération qui n’avait jamais fini pouvait encore publier des suppressions de fichiers que cet appareil n’avait pas lus. L’instantané le plus récent d’une sauvegarde pouvait vieillir et emporter avec lui la seule copie restaurable. La première rencontre avec un autre appareil pouvait rester là un quart d’heure, l’air morte. C’est pour cela que cette version existe. C’est encore une alpha, et ce n’est toujours pas pour des données que vous ne pouvez pas vous permettre de perdre. La longue liste est dans le journal des changements. Ce que vous remarquerez vraiment est ci-dessous.

## Votre téléphone en est informé

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="Un portable envoie au téléphone une alerte de manque de place sur le dossier Documents. Le coffre lui-même reste sur l’ordinateur." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="Un portable envoie au téléphone une alerte de manque de place sur le dossier Documents. Le coffre lui-même reste sur l’ordinateur." width="640" height="320"></picture>
</figure>

Un appareil peut maintenant prévenir votre téléphone, via ntfy, Pushover ou Telegram, quand une personne doit intervenir. Ajoutez un canal dans les Réglages ou avec `varsto notify`. Chaque service a un court guide et un message de test, et vous choisissez ce qu’il a le droit de dire. Les noms de dossiers, de stockages et d’appareils peuvent rester hors du texte.

Les alertes qui comptent sont activées, sauf si vous les coupez : un stockage en difficulté, un disque qui n’a plus de place, moins de copies que ce que demande une politique, des données endommagées, une sauvegarde qui a échoué ou qui est en retard, une demande qui vous attend. Les sauvegardes terminées, les nouveaux fichiers et un résumé quotidien restent silencieux tant que vous ne les demandez pas. Les jetons restent sur l’appareil, dans `notify.json`, et ne sont jamais synchronisés. Le message lui-même n’est pas chiffré de bout en bout sur le trajet via ntfy, Pushover ou Telegram, ce qu’il vaut mieux savoir avant de le laisser nommer un dossier. Un envoi raté attend et est retenté, y compris après un redémarrage. La même alerte n’est pas répétée pendant six heures, et un canal reçoit au plus vingt messages par heure. Vous pouvez le configurer pendant que le coffre est verrouillé.

## Une récupération qui a déjà les octets

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Les blocs chiffrés restent sur le portable. Une seule liaison n’emporte vers un cloud verrouillé que les blocs qui manquent." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Les blocs chiffrés restent sur le portable. Une seule liaison n’emporte vers un cloud verrouillé que les blocs qui manquent." width="640" height="320"></picture>
</figure>

L’essentiel d’un fichier modifié était déjà là. Alpha.17 cesse de récupérer ces blocs une seconde fois. Les parties inchangées d’un fichier modifié viennent de la version précédente sur le disque. Un renommage ou un déplacement vient de l’ancien chemin, ou de la corbeille si c’est là qu’il est allé. Deux copies du même fichier ne récupèrent chaque bloc distinct qu’une fois. Tout ce qui est lu localement est contrôlé par rapport à son identifiant de morceau, et un bloc qui ne correspond pas est quand même récupéré.

L’autre moitié, c’est l’appareil qui vient d’écrire le fichier. Il sert aussitôt aux autres chaque fichier qu’il a mis en place, pas seulement une fois sa propre synchronisation terminée, et les demandes sont réparties entre les pairs qui détiennent vraiment les blocs.

La première fois que cet appareil en rencontre un autre, avant que celui-ci ait lu ce certificat, le chemin est affiché comme en cours de connexion et retenté tout de suite. Un refus ultérieur attend quelques secondes et est affiché comme injoignable. Un appareil qui n’a jamais répondu ne passe plus une minute, puis jusqu’à quinze, avant le premier vrai essai. Tant que cette première synchronisation tourne encore, un dossier qui n’a pas encore de fichiers est affiché comme en cours de récupération. Ce n’est pas un dossier vide déjà terminé.

Un pair qui répondait puis échoue se repose une seconde, et le repos double, au lieu d’une minute fixe. Un bloc que personne d’autre n’a est redemandé à ce pair une fois de plus. Si le pair redémarre, la synchronisation suivante, un enregistrement de pair plus récent ou une balise du réseau local met fin au repos, au lieu de signaler chaque fichier indisponible. Les appareils qui sont simplement partis se reposent plus longtemps, et jusqu’à huit d’entre eux sont interrogés ensemble, de sorte qu’ils coûtent un délai d’attente au lieu de huit.

## Ce qu’un échec n’a plus le droit de faire

Une récupération qui échoue ne publie plus de suppressions de fichiers que cet appareil n’a pas lus. Ce que vous avez ajouté ou modifié ici est quand même envoyé. La récupération suivante va chercher les copies que les autres appareils ont encore avant qu’un fichier manquant puisse être déclaré disparu.

Si la version d’un autre appareil gagne un conflit, le fichier ici ne s’écarte qu’une fois le gagnant vraiment arrivé. Un gagnant qui n’avait pas pu être récupéré laissait le chemin vide, et l’envoi suivant publiait alors sa suppression. Un fichier qui grandit ou rétrécit pendant que le parcours le lit attend le parcours suivant. Il n’est pas publié avec une taille que ses blocs ne contiennent pas, ce qui faisait refuser à chaque autre appareil la liste entière du dossier.

Les paquets non revendiqués sont supprimés après 48 heures, ou après 24 lorsqu’un stockage local a moins de 10 % de libre. C’était sept jours. Un envoi, un import ou une sauvegarde dont l’enregistrement de carte n’a jamais été publié supprime les paquets qu’il vient d’écrire, et une réparation dont le lot n’a pas été scellé fait de même. Si le scellement échoue après la publication de l’enregistrement de carte, les paquets restent, parce que la déclaration est déjà dans le registre. `varsto gc orphans` supprime maintenant les paquets non revendiqués, si vous préférez ne pas attendre.

La conservation d’une sauvegarde ne mange plus l’instantané le plus récent seulement parce qu’il est ancien. Un répertoire source perdu, ou un appareil qui n’en a jamais pris de plus récent, faisait expirer cet instantané à la date prévue, puis en collectait les blocs, et il ne restait rien à restaurer. Arrêter la sauvegarde laisse toujours expirer le dernier instantané. Cette partie n’a pas changé, et c’est ainsi que vous dites que vous en avez fini.

## Horloges, noms, et une clé qui a survécu à l’appareil

Deux processus sur une même machine, la ligne de commande et le service en arrière-plan, ne peuvent plus réserver la même valeur de Lamport puis la distribuer tous les deux. La réservation tient un verrou sur la lecture, l’augmentation et le remplacement.

Deux appareils qui écrivent le même numéro d’époque de coffre ou de dossier ne cessent plus de signer jusqu’à ce qu’une personne choisisse. L’appareil qui voit les deux enregistrements garde celui dont l’identifiant d’émetteur est le plus grand. `varsto device resolve-epoch` et `varsto folder resolve-epoch` remplacent encore ce choix quand vous en voulez un autre.

Sur un disque qui ignore la casse, deux chemins qui ne diffèrent que par la casse ou par la normalisation Unicode reçoivent des noms locaux distincts, quel que soit celui qui arrive le premier. L’orthographe NFC l’emporte en cas d’égalité. Ensuite le plus petit chemin d’origine garde le nom simple, et l’autre devient ` (2)`.

Retirer un appareil ne change pas, à lui seul, le mot de passe chez le fournisseur de stockage. Ce qu’il fait maintenant, c’est refuser d’oublier. `varsto status` et `varsto device list` nomment chaque stockage dont cet appareil pourrait encore utiliser les identifiants pour supprimer le texte chiffré. Quand vous les avez remplacés chez le fournisseur, `varsto storage mark-rotated <name>` efface l’avertissement. Varsto ne renouvelle pas le secret à votre place.

## Les mots sur le papier, et les clés qui restaient dans un fichier

`varsto recovery kit` imprime le kit du format 3 : les mots du coffre et les mots de récupération. Il imprimait le texte du format 2, qui disait que les 24 mots du coffre lisaient tout dans le coffre. Dans le format 3, ils ouvrent les noms d’appareils, les noms de dossiers et le registre des stockages. Le contenu demande les mots de récupération. Un tirage fait sans eux le dit maintenant en capitales, au lieu d’avoir l’air complet. `--shares` divise les deux jeux.

Une demande de partage et une demande d’organisation gardaient leurs clés privées dans un fichier JSON en clair. Une copie du répertoire de l’appareil, prise pendant que la demande attendait, pouvait les lire et, une fois le propriétaire ayant approuvé, ouvrir le dossier sans aucune phrase secrète. Les clés sont maintenant scellées sous la phrase secrète de l’appareil. Afficher le code de demande exige la phrase secrète, et accepter la demande l’exige de nouveau. Une demande qu’alpha.16 a laissée en clair est scellée la prochaine fois qu’une commande la lit.

Les journaux reçoivent le même traitement pour la façon dont un afficheur de débogage écrit une valeur facultative. Une ligne comme `password: Some("…")` était coupée au guillemet et laissait le secret dans le reste de la ligne. La phrase secrète est enregistrée dans le filtre qui masque les secrets, sur chaque chemin de déverrouillage, y compris quand le service revient du trousseau. Avant, ce service pouvait tourner des jours sans que rien y soit enregistré.

## Une pause qui veut dire en pause

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="Un téléphone en pause entre un portable à la maison et un NAS au bureau. Les deux liaisons sont marquées coupées." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="Un téléphone en pause entre un portable à la maison et un NAS au bureau. Les deux liaisons sont marquées coupées." width="640" height="320"></picture>
</figure>

Mettre le service en arrière-plan en pause arrêtait la synchronisation et laissait le reste de l’appareil bavard. L’écoute, la balise du réseau local, le rendez-vous, le relais et la redirection du routeur s’arrêtent avec lui, et ils restent arrêtés jusqu’à ce que vous repreniez. Une pause que vous avez vous-même demandée survit à un redémarrage, ce qui compte sur un téléphone qui arrête et relance le service toute la journée. La courte pause que `varsto disk` ou un import prend pour lui-même n’est pas enregistrée. Celle-là finit quand la commande finit.

Les vignettes dans la liste des fichiers réapparaissent sur les téléphones. Quand le moteur était occupé, le service répondait « pas de vignette », et la page le croyait. Il répond maintenant « occupé », et la page réessaie.

La politique par défaut ne traite plus un dossier comme violé dans un coffre qui n’a ni pool de disques ni stockage sur un dossier. Il y a un seul avertissement : rien n’est sur un disque à vous, et comment en ajouter un. Une politique que vous avez réglée exprès, et qui demande vraiment une copie à la maison, y est toujours tenue. La même distinction vaut quand un import décide si sa source peut être retirée, de sorte qu’un dossier de ce coffre n’attend plus indéfiniment une copie sur un disque que vous n’avez pas.

Une commande et le service en arrière-plan prennent le même verrou pour récupérer, libérer, écrire et déplacer un fichier, de sorte qu’ils ne défont plus l’état de dossier l’un de l’autre. Un téléchargement ou une écriture qui échoue ne laisse plus un fichier `.varsto-tmp-…` ou `.varsto-upload-…` qui retiendrait une partie du contenu. Les fichiers qui arrivent d’un autre appareil gardent la date de modification que leur auteur a enregistrée, au lieu d’être datés du moment où ils ont été téléchargés. Les outils qui se fient à la date, une compilation, une photothèque, une autre sauvegarde, cessent de voir chaque fichier récupéré comme nouveau.

## Un appareil retiré le reste

Les enregistrements de dossier, les concessions et le séquestre d’un appareil retiré ne comptent que jusqu’au premier numéro de séquence qu’il a laissé vide. Il ne peut pas revenir plus tard et combler ce trou avec un enregistrement antidaté. Un membre d’un autre coffre applique un retrait qu’il lit dans l’époque du dossier. Un dossier que celui qui retire n’a pas pu doter d’une nouvelle clé en reçoit une à la prochaine synchronisation d’un propriétaire qui détient encore la clé. Ce que l’appareil retiré a déjà sur son propre disque, il le garde. C’était déjà vrai, et ça l’est encore.

Rejoindre lit le manifeste de l’organisation et ne prend les époques de coffre et les révocations que de ses administrateurs. Une révocation écrite par un membre ordinaire de la liste n’ouvre plus le coffre pour un appareil qui rejoint.

La ligne « ne détient aucune clé » du journal d’activité a le même bouton que la ligne du dossier, de sorte qu’un téléphone peut demander l’accès depuis cette ligne au lieu de chercher le dossier. Le miroir restic, et les dossiers attachés en dessous, sont créés pour que seul cet utilisateur puisse les lire.

## Le nom sur l’icône

Les identifiants d’application sont maintenant `net.varsto.app` sur Android et macOS, `net.varsto.app.ios` sur iOS, et `net.varsto.app.alpha` pour le build macOS non signé. Une application déjà installée garde son identifiant précédent, et son coffre n’est pas déplacé, jusqu’à ce que vous l’installiez de nouveau. Installer le nouveau paquet d’installation à côté de l’ancien ne le remplace pas.

## Si vous êtes sur alpha.16

Mettez à jour quand vous voulez. Les deux versions peuvent partager un coffre pendant que vous le faites. Rien dans cette version ne vous demande de réinitialiser, d’imprimer un nouveau kit, ou de désinstaller une version Android qui est déjà celle signée pour la publication depuis alpha.16. Si une demande de partage ou une demande d’organisation est encore dans un fichier en clair datant d’alpha.16, la prochaine commande qui la lit la scelle. C’est encore une alpha.
