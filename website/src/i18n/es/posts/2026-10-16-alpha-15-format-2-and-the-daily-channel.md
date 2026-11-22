---
title: Alpha.15: formato de almacenamiento 2, un instalador de Windows y un canal diario
date: 2026-10-16
summary: Un formato de almacenamiento nuevo que corrige dos hallazgos de la revisión de seguridad, así que las bóvedas que ya existen hay que crearlas de nuevo. Windows recibe un programa de instalación, una ventana nativa y actualizaciones automáticas, y hay un canal firmado de compilaciones diarias.
---
La versión actual es [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Esta nota describe una versión anterior. Las [descargas](https://varsto.net/downloads/) sirven alpha.17, y el código fuente está en [GitHub](https://github.com/janttsu/varsto).

Alpha.15 cambia el formato de almacenamiento. Eso es lo principal que hay que saber antes de actualizar: las bóvedas hechas con alpha.14 o anterior no se pueden abrir con esta versión y hay que crearlas de nuevo. El resto de la publicación es una lista larga de correcciones y de trabajo en la interfaz, una instalación de Windows como es debido, y un canal de compilaciones diarias para quien quiera probar el código más reciente.

## El formato 2 y qué significa

La revisión de seguridad que hay detrás de alpha.14 encontró dos problemas en cómo se guardaban los bloques que no se podían corregir sin cambiar el formato. El formato 2 los corrige:

- El nonce de un bloque cifrado se deriva ahora de los bytes exactos que se cifran (después de la compresión), no del texto en claro. Antes, el nonce dependía de un resultado de compresión que no estaba garantizado que fuera el mismo entre versiones de zstd.
- El cortador tiene una clave por carpeta. Los puntos de corte eran una función pública del contenido del archivo, así que un almacenamiento que conociera un archivo podía reconocerlo por los tamaños de sus bloques. Ahora el mismo archivo en dos carpetas se corta en sitios distintos.
- Cada bloque se guarda en un paquete (64 MiB, 256 MiB en almacenamientos en frío) y ningún bloque es un objeto por sí mismo, así que un almacenamiento ve tamaños de paquete y no los tamaños ni el número de bloques de dentro. Los paquetes tienen índices cifrados, y los bloques borrados se siguen por carpeta y se reescriben para quitarlos.
- La compresión es zstd de nivel 3 después de una prueba rápida: el texto se comprime casi igual de bien que antes y se escribe varias veces más rápido.

Lo que el formato 2 no corrige: las listas de archivos y las épocas del uso compartido se siguen aceptando solo con la clave de la carpeta, porque cerrar eso necesita manifiestos firmados y épocas del uso compartido, que pertenecen a la capa de registros del formato siguiente. Hasta que exista, quien tiene la clave de una carpeta aún puede cambiar lo que esa carpeta muestra, y las réplicas no confiables y las carpetas compartidas hay que tratarlas así. Los dos hallazgos críticos siguen abiertos en alpha.15.

**Crear de nuevo una bóveda.** No hay migración. Alpha.15 rechaza una bóveda anterior cuando la abre o cuando un dispositivo se une a través de su almacenamiento, y el mensaje dice qué hacer. Deja tus archivos donde están, y luego:

1. Conserva el binario de alpha.14 por si necesitas leer la bóveda antigua.
2. `varsto reset --yes` en el dispositivo, y luego `varsto init`.
3. Vuelve a añadir los almacenamientos y sincroniza las carpetas.

Alpha.14 rechaza una bóveda de formato 2 del mismo modo, así que las dos versiones no pueden compartir una bóveda en ninguno de los dos sentidos.

## Windows: el instalador, una ventana nativa y actualizaciones automáticas

El zip portable ya no está. Windows tiene ahora una sola descarga, `Varsto-<version>-setup.exe`: actualiza encima de lo instalado, puede reparar una instalación, y su desinstalador conserva tu carpeta de datos. La interfaz se abre en una ventana nativa (WebView2) que recuerda su tamaño y su posición, una ventana por usuario, y la bandeja la arranca. Las copias instaladas por el programa de instalación buscan actualizaciones una vez al día, verifican el programa de instalación firmado y lo instalan en silencio. Si aún ejecutas una copia portable descomprimida, `varsto update` te dice que ejecutes el instalador una vez; después las actualizaciones siguen solas.

## Todo lo demás desde alpha.14

- Un resumen de carpetas con un indicador de seguridad por carpeta: 100 % en almacenamiento externo, 100 % solo en tus propios discos, protegida en parte, o solo en dispositivos.
- Una visualización en directo de dispositivos, almacenamientos, discos y la nube, con flujos animados, y pantalla completa de verdad en el navegador y en las envolturas de Android, macOS y Windows (Esc sale).
- Reenvío: un dispositivo acoplado a una carpeta, incluso con sincronización selectiva, puede llevar los bloques de otros dispositivos a los almacenamientos en los que puede escribir, así que las fotos de un teléfono llegan a un bucket para el que solo el portátil tiene credenciales. El diálogo de acoplar pregunta ahora si la sincronización es completa o selectiva, y la dirección.
- El emparejamiento ofrece cada dirección local utilizable, la mejor primero, y unirse recurre a ellas y a una búsqueda en la red local, con el progreso a la vista y un error que nombra lo que se intentó.
- Los datos nuevos tienen un periodo de gracia antes de que la verificación informe de un incumplimiento: los bloques guardados dentro del mayor entre la ventana de verificación y 24 horas se muestran como «verificación pendiente».
- La interfaz sigue siendo usable durante sincronizaciones largas: cuando el servicio está ocupado, las lecturas se responden con la última respuesta conservada, las listas se dibujan poco a poco, y la página no se recarga nunca.
- Correcciones: el vaciado y la ubicación rechazan ahora elecciones contradictorias, miniaturas para almacenamientos añadidos más tarde, los teléfonos aceptan solo almacenamientos S3 y rclone, las fotos y los vídeos que ya están en un teléfono se copian primero los más nuevos, la impresión del paquete de recuperación, el icono del Dock de macOS, el botón Atrás y el teclado de Android, `reset` y los reinicios del servicio, y la inicialización de unidades con una disposición GPT moderna.
- Un `.ipa` de iOS sin firmar para AltStore, SideStore y Sideloadly.
- El sitio web tiene una traducción al francés, y las páginas en finés y en sueco muestran capturas de la interfaz en su propio idioma.

## El canal diario

`varsto update --daily` instala la compilación diaria más reciente de la línea principal. Las compilaciones diarias se hacen para todas las plataformas cada vez que se mueve la rama principal, y se publican en varsto.net/daily/. La lista de sumas de comprobación se firma con una clave diaria distinta de la clave de publicación: el actualizador confía en cada clave solo para su propio canal, así que una firma diaria nunca valida una publicación, ni al revés. También rechaza las listas caducadas, las que vienen del futuro o las más antiguas que la compilación que ejecutas. El actualizador en segundo plano y la interfaz se quedan en las publicaciones; el canal diario solo se arranca a mano.

Las compilaciones diarias son compilaciones de desarrollo. No son para datos de producción, y una compilación diaria puede traer un cambio de formato de almacenamiento antes que cualquier publicación.

## Compatibilidad

Todos los dispositivos de una bóveda tienen que ejecutar alpha.15. Alpha.14 no puede leer una bóveda de alpha.15 y alpha.15 no puede leer una bóveda de alpha.14, y ninguna lee los paquetes ni las listas de marcas de muerto de la otra. Actualiza todos los dispositivos a la vez y crea de nuevo la bóveda como se describe arriba.
