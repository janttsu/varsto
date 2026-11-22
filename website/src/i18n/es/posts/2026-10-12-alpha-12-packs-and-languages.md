---
title: Alpha.12: los archivos pequeños en paquetes, y Varsto en finés y en sueco
date: 2026-10-12
summary: Los bloques cifrados pequeños se escriben ahora en paquetes, así que una carpeta de 20 000 archivos pequeños se convierte en 79 objetos en un bucket en lugar de 20 000. La interfaz, la bandeja, la barra de menús, las envolturas móviles y este sitio web están en finés y en sueco, además de en inglés.
---
Alpha.12 tiene dos temas: menos objetos en tu almacenamiento, y la interfaz en más idiomas.

## Bloques pequeños en paquetes

Hasta ahora cada bloque cifrado era un objeto propio en el almacenamiento. Es simple y robusto, pero una carpeta con muchos archivos pequeños, como notas, código fuente o los archivos que acompañan a una fototeca, se convierte en decenas de miles de objetos diminutos. Muchos proveedores cobran por petición, algunos por objeto, y listarlos y comprobarlos todos es lento.

Desde esta versión, los bloques de hasta 128 KiB se reúnen en paquetes de unos 4 MiB o 256 miembros. Un paquete se escribe con un índice que nombra a sus miembros y dónde empieza cada uno, y un miembro se lee con una petición por rango, así que leer un archivo pequeño sigue descargando solo sus propios bytes. Los bloques grandes se siguen escribiendo de uno en uno. Los paquetes se usan en buckets S3, remotos de rclone y directorios; el almacenamiento en frío, los grupos de discos y los discos transportadores siguen con objetos sueltos.

En el laboratorio, una carpeta de 20 000 archivos pequeños llegó al bucket como 79 paquetes en lugar de 20 000 objetos. Después de la pasada se comprobó cada miembro contra su nombre.

Borrar un bloque que vive en un paquete escribe una marca de borrado pequeña, y el propio paquete desaparece cuando ya no queda ningún miembro. La reparación, la verificación, las réplicas, los movimientos de datos y quitar un almacenamiento entienden los paquetes. El formato de almacenamiento se describe en la sección 30 de la [especificación del formato](../docs/alpha-0-format.html).

No hay compatibilidad con las versiones anteriores: un dispositivo con alpha.11 o anterior no ve los bloques que están en paquetes. Actualiza todos los dispositivos.

## Fallos encontrados por el camino

Las pasadas del laboratorio encontraron problemas que las pruebas unitarias no habían visto:

- `rclone serve s3` responde a una lectura por rango con el estado 200 y solo los bytes pedidos. Varsto ahora acepta eso además del 206 habitual, así que los paquetes se leen bien desde esos servidores.
- Un dispositivo que acababa de leer los índices de paquetes no volvía a buscar paquetes que otro dispositivo había escrito momentos después. Una lectura que no encuentra ahora recarga los índices al momento.
- Un dispositivo podía fiarse de un índice de paquetes después de que otro dispositivo hubiera borrado miembros de él. Antes de decidir que un bloque ya existe y no hace falta escribirlo, Varsto comprueba ahora que sigue en su paquete.
- Los grupos de discos y los demás almacenamientos sin paquetes vuelven a escribir sus bloques de uno en uno, así que un disco lleno o ausente se informa como tal, en lugar de hacer fallar toda la subida.
- Un servidor S3 cuyo reloj se desvía más de unos minutos se corrige ahora en los dos sentidos, también cuando responde con el estado 400 en lugar de 403.

## Finés y sueco

La interfaz de escritorio, la bandeja y la barra de menús de macOS, las envolturas de Android y de iOS, y este sitio web están ahora en finés y en sueco. El inglés sigue siendo el idioma por defecto. El idioma se elige en los ajustes de la interfaz o al pie de la barra lateral, y la bandeja y las aplicaciones siguen la misma elección. La línea de comandos, la documentación y todo lo del repositorio siguen en inglés.

Las traducciones de los textos críticos para la seguridad, como los de borrar, revocar dispositivos y las palabras de recuperación, están marcadas para que las revisen hablantes nativos. Las correcciones son bienvenidas.

## Construye Varsto con nosotros

La nueva página [Contribuir](../contribute/) describe cómo se construye Varsto y dónde hace falta ayuda: una revisión de la criptografía y del formato de almacenamiento, Windows, iOS y Android, el cruce de NAT en redes distintas de las del mantenedor, más proveedores de S3, el empaquetado y las traducciones.
