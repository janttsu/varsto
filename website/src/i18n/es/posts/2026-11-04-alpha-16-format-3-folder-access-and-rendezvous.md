---
title: Alpha.16: formato de almacenamiento 3, acceso a las carpetas por aprobación y un servicio de rendezvous
date: 2026-11-04
summary: Un formato de almacenamiento nuevo, con un libro mayor a nivel de paquete, registros firmados y palabras de recuperación, así que las bóvedas que ya existen hay que crearlas de nuevo. Una carpeta se abre a un dispositivo con la aprobación de un propietario. Los dispositivos se encuentran a través de un servicio de rendezvous opcional. Unirse y los cambios de miembros funcionan sin conexión, y hay importaciones desde torrents y YouTube.
---
La versión actual es [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Esta nota describe una versión anterior. Las [descargas](https://varsto.net/downloads/) sirven alpha.17, y el código fuente está en [GitHub](https://github.com/janttsu/varsto).

Alpha.16 vuelve a cambiar el formato de almacenamiento. Eso es lo principal que hay que saber antes de actualizar: las bóvedas hechas con alpha.15 o anterior no se pueden abrir con esta versión y hay que crearlas de nuevo. El resto de la publicación es una lista larga de cambios en cómo se unen los dispositivos, cómo se encuentran y cómo aguantan una red mala, una página Importar nueva, y un conjunto grande de correcciones y de refuerzo a partir de una revisión del formato nuevo.

## Crear de nuevo una bóveda

No hay migración. Alpha.16 rechaza una bóveda anterior cuando la abre o cuando un dispositivo se une a través de su almacenamiento, y el mensaje dice qué hacer. Alpha.15 rechaza una bóveda de formato 3 del mismo modo, así que las dos versiones no pueden compartir una bóveda en ninguno de los dos sentidos. Todos los dispositivos de una bóveda tienen que ejecutar alpha.16. Deja tus archivos donde están, y luego:

1. Conserva el binario de alpha.15 por si necesitas leer la bóveda antigua.
2. `varsto reset --yes` en el dispositivo, y luego `varsto init`. Imprime un kit con dos conjuntos de palabras: las palabras de la bóveda y, nuevas en el formato 3, las palabras de recuperación. Guarda las dos.
3. Vuelve a añadir los almacenamientos, añade las carpetas (aquí se piden las palabras de recuperación) y sincroniza.

## Android: desinstala primero el APK antiguo

El paquete de Android es ahora un APK firmado para la publicación (`varsto-<version>-android.apk`), no una compilación de depuración, así que una publicación posterior se instala encima como actualización. Está firmado con una clave nueva. Una instalación de un APK de depuración anterior (alpha.15, o una compilación diaria más antigua) no se puede actualizar a este: Android rechaza la actualización. Desinstala primero la aplicación antigua y luego instala la nueva. Desinstalar quita la copia de la bóveda de ese dispositivo, así que asegúrate de que la bóveda tenga otro dispositivo o un almacenamiento antes de hacerlo. La descarga diaria de Android sigue siendo una compilación de depuración, con el nombre `varsto-daily-android-debug.apk`.

## Formato de almacenamiento 3

El formato 3 se describe en la sección 77 de la especificación y en el documento de diseño del formato 3. Lo que cambia para quien lo usa:

- El libro mayor ya no lista cada bloque. Declara paquetes de unos pocos tamaños fijos (de 256 KiB a 64 MiB, con relleno), así que un almacenamiento ve clases de tamaño y no cuántos bloques o archivos hay.
- Cada objeto publicado que no sea un paquete es un registro firmado que nombra la clave con la que está sellado. Los manifiestos, las listas de la papelera y las instantáneas son una base más deltas pequeños, y cada carpeta guarda un mapa de bloques firmado por cada dispositivo que escribe.
- La clave de una carpeta llega a un dispositivo solo como una concesión que aprobó un propietario. Un dispositivo que se une con las palabras de la bóveda ve los nombres de las carpetas y no tiene el contenido; lo pide con `varsto folder request`, un propietario compara seis palabras que se muestran en los dos dispositivos y aprueba con `varsto folder approve` (también `requests`, `deny`, `members`, `role`). El servicio en segundo plano no aprueba nunca. La interfaz tiene una tarjeta Acceso a la carpeta en la página Archivos.
- Cada época de la clave de carpeta tiene una copia de recuperación bajo las palabras de recuperación. `varsto folder add` la crea, `varsto recovery escrow` escribe más tarde una que falte, y `varsto status` avisa hasta entonces. `varsto join --recovery-words` abre cada carpeta que tiene una copia de recuperación.
- Los pares hablan solo por TLS, con tokens atados a la conexión, y comparan hasta dónde llega el libro mayor de cada uno, así que se nota un almacenamiento que oculta lotes o los revierte, y lo dicen la página Ayuda y una notificación.
- Quitar un dispositivo ahora se mantiene: a un dispositivo revocado no se le concede la siguiente clave de carpeta, y sus registros dejan de contar en el momento de quitarlo.

## Encontrarse: el servicio de rendezvous

Los dispositivos pueden encontrarse entre redes a través de un servicio de rendezvous opcional, por defecto `https://varsto.net/rv`. Un dispositivo deja allí su registro de par sellado, lee los registros de la bóveda, aprende su propia dirección pública y, cuando ninguna dirección responde, alcanza a un par mediante una perforación coordinada o, como último camino, un relé cifrado de extremo a extremo (se muestra como `relayed via rendezvous`). Un dispositivo que se une y no encuentra nada en su red puede buscar una oferta por código o por enlace y emparejarse a través del relé. El servicio ve etiquetas, direcciones IP y cuentas de bytes, nunca la identidad de la bóveda ni el contenido. Lo cambian `varsto p2p rendezvous set <url> | on | --off | status` o la página Pares, y el servidor se puede alojar uno mismo (`varsto-rendezvous`, un binario estático de Linux en la compilación diaria; el puerto UDP por defecto es 3334). Todo funciona también sin él.

## Una red mala y trabajar sin conexión

- Un almacenamiento al que no se llega ya no hace fallar toda una sincronización. Se marca como caído durante esa pasada y descansa entre pasadas, y los otros almacenamientos siguen; lo que se perdió se copia allí más tarde.
- Las llamadas a S3 y a rclone tienen límites de tiempo que se ajustan al tamaño de la transferencia, reintentos y subidas multiparte que se pueden reanudar, así que un enlace lento cuesta segundos, no minutos.
- La transferencia de par a par funciona sin ningún almacenamiento, a partir de un directorio de pares guardado, así que la sincronización en la LAN funciona sin internet.
- Unirse por emparejamiento ya no necesita que responda un almacenamiento, y los cambios de miembros (añadir una carpeta, aprobar, cambiar un papel, compartir) se guardan primero en el dispositivo y se envían cuando un almacenamiento responde. `varsto status` dice «N changes waiting to upload» (N cambios esperando a subirse).
- Las acciones locales (importaciones, la página Papelera, las miniaturas, las escrituras de archivos) terminan mientras un almacenamiento está caído e informan de «upload pending» (subida pendiente).
- La interfaz, la bandeja, la línea de comandos y MCP ya no se quedan congelados mientras una sincronización espera un enlace muerto.

## Importaciones

- Una sola página Importar para cada origen (una carpeta o un disco, un repositorio git-annex, una unidad en la nube a través de rclone, un torrent, YouTube), con una lista de las importaciones en curso.
- `varsto import torrent` importa torrents más grandes que el disco, en tandas que conservan una reserva de espacio libre; un archivo sale del disco de descarga solo cuando sus bloques están en un almacenamiento y se cumple la política de conservación de la carpeta.
- `varsto import youtube` archiva canales, listas de reproducción y vídeos en carpetas con yt-dlp, con valores por defecto corteses y una reserva de espacio libre.

## Discos y servidores

- `varsto mailbox` deja preparados los bloques de un disco acoplado para un disco del grupo o un almacenamiento que está fuera, en una bandeja de salida duradera y comprobada por hash, así que un bloque que solo está en el disco A llega al disco B cuando se acopla B.
- `varsto service remember` funciona sin una sesión de escritorio (por SSH, en servidores) a través de `systemd-creds` o del llavero del núcleo; `varsto service forget` lo quita.
- `varsto service stop` ahora se queda parado, y una actualización del propio programa sigue reiniciando el servicio.

## Correcciones y refuerzo

- Una descarga ya no sobrescribe un archivo editado después del examen, y un archivo malo ya no detiene la descarga o la subida de una carpeta. Un archivo o un directorio que no se puede leer se cuenta, en lugar de hacer que los archivos que hay debajo parezcan borrados.
- Miembros: quitar un dispositivo vale para quien se une después y para las carpetas a las que no se les cambió la clave, y solo se adopta una época, una revocación o una orden de borrado de un administrador.
- El vaciado, quitar un almacenamiento y la limpieza después de insertar un disco conservan cualquier paquete que pueda ser la única copia. Están corregidas la reparación, la subida después de un lote que falta y acoplar después de desacoplar.
- Las lecturas por rango de S3 ya no hacen que `fsck` dé todos los paquetes por cortos.
- La visualización muestra una nota de carga o una nota de bóveda vacía en lugar de la escena de ejemplo, y las miniaturas se ven en la página.
- Las negociaciones TLS tienen un plazo que se cumple, y una dirección puede tener como mucho 64 sin terminar. Un cliente local atascado ya no puede congelar la API local. El servidor de rendezvous tiene un límite de ritmo por clase de petición y una memoria acotada para las búsquedas. Los avisos de dependencias que informa `cargo audit` están parcheados.
- Los flujos de trabajo de GitHub se ejecutan con permisos de solo lectura, salvo donde publican.

## Compatibilidad

Todos los dispositivos de una bóveda tienen que ejecutar alpha.16. Alpha.15 no puede leer una bóveda de alpha.16 y alpha.16 no puede leer una bóveda de alpha.15. Actualiza todos los dispositivos a la vez y crea de nuevo la bóveda como se describe arriba. Esto sigue siendo una alfa: no es para datos de producción. La lista completa está en el registro de cambios.
