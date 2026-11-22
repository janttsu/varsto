---
title: Alpha.13: copias de seguridad que nada puede cambiar
date: 2026-10-13
summary: Elige una carpeta en cualquier dispositivo y Varsto guarda de ella instantáneas cifradas y de solo lectura en tus almacenamientos externos, nunca en tus dispositivos, durante los días que elijas (90 por defecto). Las restauraciones van a un directorio que nombras, desde la aplicación o la línea de comandos.
---
La sincronización deja todas las copias iguales, que es justo lo que no quieres cuando un archivo se borra por error o lo cifra un ransomware: el daño llega a todos los dispositivos. Alpha.13 añade copias de seguridad, que funcionan al revés.

## Cómo funciona

Eliges una carpeta en un dispositivo y le pones un nombre a la copia de seguridad. Varsto toma una instantánea: la lista de archivos y cada bloque, cifrados como todo lo demás que guarda. Las instantáneas van solo a almacenamientos externos (buckets S3, remotos de rclone, recursos compartidos de NAS, directorios y almacenamiento en frío), nunca a discos transportadores y nunca a tus otros dispositivos. Tus otros dispositivos ven que la copia de seguridad existe y qué instantáneas tiene, pero no descargan su contenido.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Las instantáneas se toman a diario por defecto, cada semana o solo cuando lo pides (`varsto backup take`). Los bloques que no cambiaron se guardan una vez, por muchas instantáneas que los usen.

## De solo lectura y conservadas un tiempo fijado

Una instantánea no se edita nunca después de tomarla. Su fecha de caducidad queda sellada dentro al escribirla, así que cambiar después el plazo de conservación solo afecta a las instantáneas nuevas. Cuando una instantánea ha caducado, el dispositivo que hizo la copia de seguridad la borra de los almacenamientos. Solo se borran los bloques que ya no necesita ninguna instantánea que quede, y un día de gracia admite relojes un poco desviados. Si ese dispositivo ya no está, lo hace un poco más tarde cualquier otro dispositivo de la bóveda. Parar una copia de seguridad no toma instantáneas nuevas, pero no borra nada antes de tiempo.

## Restaurar

Una restauración va siempre a un directorio que tú nombras, y ese directorio tiene que estar vacío salvo que permitas sobrescribir. Puedes elegir la instantánea más reciente, una numerada o la más reciente en una fecha o anterior, y restaurar todo o solo algunas rutas. La aplicación tiene una página Copias de seguridad que hace lo mismo.

## Detalles y límites

El formato está en la sección 31 de la [especificación](../docs/alpha-0-format.html). En esta primera versión, la caducidad sigue el reloj de cada dispositivo, las políticas de conservación aún no cubren las copias de seguridad, y la vista de dónde están los datos no las muestra.

Las versiones anteriores no entienden las copias de seguridad: actualiza a alpha.13 todos los dispositivos de una bóveda antes de añadir una.
