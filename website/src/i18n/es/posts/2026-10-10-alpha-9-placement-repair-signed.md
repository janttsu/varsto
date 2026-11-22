---
title: Alpha.9: los datos donde tú quieres, reparación por sí sola, actualizaciones firmadas y cada plataforma compilada a la vista
date: 2026-10-10
summary: Las carpetas se pueden colocar en los almacenamientos que elijas y mover entre ellos, las copias perdidas se reparan solas, las actualizaciones se firman con una clave fuera de línea, las descargas de par a par piden muchos bloques a la vez, y cada paquete se compila, se prueba y se fotografía ahora en los runners de GitHub.
---
Alpha.9 (una compilación que nunca se etiquetó por sí sola; sus cambios salieron en alpha.10) mira a largo plazo: decidir dónde viven los datos, devolverlos a las copias que pide tu política sin que tengas que hacerlo tú, y fiarte de la actualización que trae la siguiente versión.

## Los datos donde tú quieres

Cada carpeta puede tener ahora una ubicación: los almacenamientos a los que van sus bloques. Los datos se pueden mover de un almacenamiento a otro (una carpeta entera, o solo los archivos inactivos desde hace unos días), bloque a bloque; cada bloque se escribe y se vuelve a leer en el almacenamiento nuevo antes de borrar la copia antigua, y un movimiento interrumpido sigue sin más cuando se vuelve a ejecutar. Un grupo de discos extraíbles puede pedir copias en discos que se guardan en lugares distintos, por ejemplo uno en casa y uno en el trabajo, y Varsto llena cada disco con lo que a su lugar aún le falta.

## Reparación por sí sola

Cuando falta una copia, se quita un almacenamiento o falla una verificación, el dispositivo que tiene los datos vuelve a poner el bloque donde lo quieren la política de conservación y la ubicación de la carpeta, desde sus propios archivos, la caché de bloques cifrados, otro almacenamiento o un par. La cola de reparación se ve en la interfaz y con `varsto repair`.

## Actualizaciones firmadas

La lista de sumas de comprobación de cada publicación se firma ahora con la clave de publicación del proyecto, que no sale nunca de la máquina del mantenedor, y el actualizador rechaza una publicación que no lleve esa firma. También compara la suma con la que va adjunta a la publicación de GitHub, un segundo canal. `varsto verify-release` comprueba una descarga a mano, y `minisign` también. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) explica el esquema.

## Más rápido de par a par

Las descargas mantienen hasta ocho bloques en vuelo (entonces), piden por adelantado los archivos pequeños de una carpeta y comparten una conexión por par; un dispositivo que sirve bloques ya no arranca una sincronización completa propia cada pocos segundos. Las [mediciones](../benchmarks/) comparan París, Ámsterdam y Varsovia, de par a par frente a un bucket S3.

## Compilado a la vista

Cada plataforma se compila y se prueba ahora en los runners de GitHub con cada cambio: los paquetes de Linux y de Windows (el de Windows, probado en Windows Server 2025, incluidas las entradas del menú del Explorador), la aplicación de Android en el emulador, la imagen de disco de macOS y la aplicación de iOS en Apple Silicon. Las mismas ejecuciones toman las [capturas de pantalla](../screenshots/), así que las imágenes de este sitio siguen la compilación más reciente.

## Y más

Al compartir se anota quién pidió acceso, por la huella; quitar a un miembro pasa lo compartido a claves nuevas, y a un Strongroom se le puede cambiar la clave; los archivos se pueden descargar o liberar desde el gestor de archivos en Linux (Nautilus, Dolphin, Nemo) y en Windows (Explorador); las filas de carpeta conservan sus dos botones principales y ponen el resto en un menú; la aplicación de macOS y las del teléfono dicen cuándo hay una versión más nueva en la página de descargas, en lugar de darse por al día; y los lotes grandes del libro mayor ya no fallan en S3.

## Actualiza todos los dispositivos antes de mover datos

Mover datos escribe un tipo nuevo de entrada del libro mayor que alpha.8 y las anteriores no saben leer: sus sincronizaciones fallarían desde el primer movimiento. Actualiza primero todos tus dispositivos. A partir de esta versión, las entradas desconocidas se saltan, así que lo que se añada después no la romperá. Los clientes hasta alpha.8 comprueban solo la suma de comprobación al actualizarse; esta publicación es la primera cuyo actualizador exige la firma.

## Sigue siendo una alfa

La criptografía no se ha auditado, el formato aún puede cambiar y un fallo puede destruir datos. Usa datos de prueba y conserva tus propias copias de seguridad.
