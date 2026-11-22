---
title: Alpha.17: la bóveda se queda, los fallos silenciosos se van
date: 2026-11-22
summary: Ni un formato de almacenamiento nuevo ni palabras nuevas que anotar. Alpha.17 es la versión que impide que una sincronización fallida borre archivos, conserva la última copia de seguridad y avisa a tu teléfono cuando algo va mal de verdad.
---
Puedes actualizar esta sin ceremonia. Alpha.17 abre una bóveda de alpha.16 tal como está. No hay un formato nuevo, ni un segundo conjunto de palabras, ni nada que crear de nuevo. Lo que cambia es la clase de error que antes ocurría mientras mirabas otra cosa.

Una descarga que no llegaba a terminar podía publicar igualmente borrados de archivos que este dispositivo no había leído. La instantánea más reciente de una copia de seguridad podía envejecer y llevarse la única copia que se podía restaurar. El primer encuentro con otro dispositivo podía quedarse ahí un cuarto de hora, con aspecto de muerto. Para eso es esta versión. Sigue siendo una alfa, y sigue sin ser para datos que no te puedas permitir perder. La lista larga está en el registro de cambios. Abajo está lo que sí vas a notar.

## Tu teléfono se entera

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="Un portátil envía al teléfono un aviso de poco espacio sobre la carpeta Documentos. La bóveda en sí se queda en el ordenador." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="Un portátil envía al teléfono un aviso de poco espacio sobre la carpeta Documentos. La bóveda en sí se queda en el ordenador." width="640" height="320"></picture>
</figure>

Un dispositivo puede avisar ahora a tu teléfono, por ntfy, Pushover o Telegram, cuando algo necesita a una persona. Añades un canal en Ajustes o con `varsto notify`. Cada servicio tiene una guía corta y un mensaje de prueba, y tú eliges qué puede decir. Los nombres de carpeta, de almacenamiento y de dispositivo pueden quedarse fuera del texto.

Las alertas que importan están activas salvo que las apagues: un almacenamiento en apuros, un disco que se queda sin sitio, menos copias de las que pide una política de conservación, datos dañados, una copia de seguridad que falló o está fuera de plazo, una solicitud que te espera. Las copias de seguridad terminadas, los archivos nuevos y un resumen diario se quedan en silencio hasta que los pidas. Los tokens viven en el dispositivo, en `notify.json`, y no se sincronizan nunca. El propio mensaje no va cifrado de extremo a extremo al pasar por ntfy, Pushover o Telegram, y conviene saberlo antes de dejar que nombre una carpeta. Un envío que falla espera y se vuelve a intentar, también después de un reinicio. La misma alerta no se repite durante seis horas, y un canal recibe como mucho veinte mensajes por hora. Puedes configurarlo con la bóveda bloqueada.

## Una descarga que ya tiene los bytes

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Los bloques de texto cifrado se quedan en el portátil. Un solo enlace lleva a una nube con candado únicamente los bloques que faltan." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Los bloques de texto cifrado se quedan en el portátil. Un solo enlace lleva a una nube con candado únicamente los bloques que faltan." width="640" height="320"></picture>
</figure>

Casi todo un archivo cambiado ya estaba aquí. Alpha.17 deja de volver a pedir esos bloques. Las partes que no cambiaron de un archivo cambiado salen de la versión anterior que hay en el disco. Un renombrado o un movimiento sale de la ruta antigua, o de la papelera si fue allí. Dos copias del mismo archivo piden cada bloque distinto una sola vez. Lo que se lee en local se comprueba contra el identificador de su fragmento, y un bloque que no coincide se pide al final de todos modos.

La otra mitad es el dispositivo que acaba de escribir el archivo. Sirve a los demás, al momento, cada archivo que ya ha dejado en su sitio, no solo cuando ha terminado su propia sincronización, y las peticiones se reparten entre los pares que de verdad tienen los bloques.

La primera vez que este dispositivo se encuentra con otro, antes de que ese otro haya leído este certificado, el camino se muestra como conectando y se vuelve a intentar al momento. Un rechazo posterior espera unos segundos y se muestra como inalcanzable. Un dispositivo que no ha respondido nunca ya no se gasta un minuto, y luego hasta quince, antes del primer intento de verdad. Mientras esa primera sincronización sigue en marcha, una carpeta que aún no tiene archivos se muestra como obteniendo. No es una carpeta vacía que ya haya terminado.

Un par que respondía y luego falla descansa un segundo, y el descanso se duplica, en lugar de un minuto fijo. Un bloque que no tiene nadie más se le pide a ese par una vez más. Si el par se reinicia, la siguiente sincronización, un registro de par más nuevo o una baliza de la LAN acaban el descanso, en lugar de informar de que todos los archivos no están disponibles. Los dispositivos que simplemente ya no están descansan más tiempo, y se pregunta hasta a ocho a la vez, así que cuestan un tiempo de espera, no ocho.

## Lo que un fallo ya no tiene permitido hacer

Una descarga que falla ya no publica borrados de archivos que este dispositivo no ha leído. Lo que añadiste o editaste aquí se sigue subiendo. La siguiente descarga trae las copias que los otros dispositivos aún tienen, antes de que un archivo que falta se pueda dar por desaparecido.

Si la versión de otro dispositivo gana un conflicto, el archivo de aquí se aparta solo cuando el ganador ha llegado de verdad. Un ganador que no se podía obtener dejaba la ruta vacía, y la siguiente subida publicaba entonces un borrado. Un archivo que crece o encoge mientras el examen lo está leyendo espera al examen siguiente. No se publica con un tamaño que sus bloques no sostienen, cosa que hacía que todos los demás dispositivos rechazaran la lista entera de la carpeta.

Los paquetes sin reclamar se borran a las 48 horas, o a las 24 cuando un almacenamiento local está por debajo del 10 % libre. Eran siete días. Una subida, una importación o una copia de seguridad cuyo registro de mapa no llegó a publicarse borra los paquetes que acaba de escribir, y lo mismo hace una reparación cuyo lote no se selló. Si el sello falla después de que el registro de mapa se publicó, los paquetes se quedan, porque la declaración ya está en el libro mayor. `varsto gc orphans` borra ahora los paquetes sin reclamar, si prefieres no esperar.

El plazo de conservación de una copia de seguridad ya no se come la instantánea más reciente solo porque sea antigua. Un directorio de origen perdido, o un dispositivo que nunca tomó una más nueva, hacía caducar esa instantánea en su fecha y luego recogía sus bloques, y no quedaba nada que restaurar. Parar la copia de seguridad sigue dejando que caduque la última instantánea. Esa parte no cambia, y es la forma de decir que has terminado con ella.

## Relojes, nombres y una clave que sobrevivió al dispositivo

Dos procesos en una misma máquina, la línea de comandos y el servicio en segundo plano, ya no pueden reservar el mismo valor de Lamport y entregarlo los dos. La reserva mantiene un bloqueo durante la lectura, el incremento y el reemplazo.

Dos dispositivos que escriben el mismo número de época de la bóveda o de la carpeta ya no dejan de firmar hasta que una persona elige. El dispositivo que ve los dos registros se queda con el de mayor identificador de emisor. `varsto device resolve-epoch` y `varsto folder resolve-epoch` siguen sustituyendo esa elección cuando quieres otra.

En un disco que ignora las mayúsculas, dos rutas que solo se diferencian en las mayúsculas o en la normalización Unicode reciben nombres locales distintos, llegue cual llegue primero. En un empate gana la grafía NFC. Después, la ruta original menor se queda el nombre llano, y la otra pasa a ser ` (2)`.

Quitar un dispositivo no cambia, por sí solo, la contraseña en el proveedor de almacenamiento. Lo que hace ahora es negarse a olvidarlo. `varsto status` y `varsto device list` nombran cada almacenamiento cuyas credenciales ese dispositivo aún podría usar para borrar texto cifrado. Cuando las hayas sustituido en el proveedor, `varsto storage mark-rotated <name>` quita el aviso. Varsto no rota el secreto por ti.

## Las palabras en papel, y las claves que antes estaban en un archivo

`varsto recovery kit` imprime el kit del formato 3: las palabras de la bóveda y las palabras de recuperación. Antes imprimía el texto del formato 2, que te decía que las 24 palabras de la bóveda leían todo lo de la bóveda. En el formato 3 abren los nombres de los dispositivos, los nombres de las carpetas y el libro mayor del almacenamiento. El contenido necesita las palabras de recuperación. Una impresión hecha sin ellas lo dice ahora en mayúsculas, en lugar de parecer completa. `--shares` parte los dos conjuntos.

Una solicitud de uso compartido y una solicitud de organización guardaban sus claves privadas en un archivo JSON en claro. Una copia del directorio del dispositivo, tomada mientras la solicitud esperaba, podía leerlas y, una vez que el propietario aprobaba, abrir la carpeta sin ninguna frase de contraseña. Las claves van ahora selladas bajo la frase de contraseña del dispositivo. Mostrar el código de solicitud la pide, y aceptar la solicitud la pide otra vez. Una solicitud que alpha.16 dejó en claro se sella la próxima vez que un comando la lee.

Los registros reciben el mismo trato en la forma en que la depuración escribe un valor opcional. Una línea como `password: Some("…")` se cortaba en la comilla y dejaba el secreto en el resto de la línea. La frase de contraseña se registra en el filtro que tapa los secretos en cada camino de desbloqueo, incluido el servicio al volver del llavero. Antes, ese servicio podía estar días en marcha sin nada registrado.

## Una pausa que significa en pausa

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="Un teléfono en pausa entre un portátil de casa y un NAS de la oficina. Los dos enlaces figuran como apagados." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="Un teléfono en pausa entre un portátil de casa y un NAS de la oficina. Los dos enlaces figuran como apagados." width="640" height="320"></picture>
</figure>

Pausar el servicio en segundo plano paraba la sincronización y dejaba al resto del dispositivo hablando. El oyente, la baliza de la LAN, el rendezvous, el relé y la asignación de puertos del router se paran ahora con él, y siguen parados hasta que reanudas. Una pausa que pones tú sobrevive a un reinicio, y eso importa en un teléfono que para y arranca el servicio todo el día. La pausa corta que `varsto disk` o una importación se toman para sí no se guarda. Esa acaba cuando acaba el comando.

Las miniaturas de la lista de archivos vuelven a verse en los teléfonos. Cuando el motor estaba ocupado, el servicio respondía que no había miniatura, y la página se lo creía. Ahora responde que está ocupado, y la página lo vuelve a intentar.

La política por defecto ya no da una carpeta por incumplida en una bóveda que no tiene grupo de discos ni almacenamiento de directorio. Hay un solo aviso: que no hay nada en un disco tuyo, y cómo añadir uno. Una política que pusiste a propósito, y que de verdad pide una copia en casa, se sigue exigiendo. La misma distinción vale cuando una importación decide si se puede quitar su origen, así que una carpeta de esa bóveda ya no espera para siempre una copia en un disco que no tienes.

Un comando y el servicio en segundo plano toman el mismo bloqueo para obtener, liberar, escribir y mover un archivo, así que ya no se deshacen el estado de carpeta el uno al otro. Una descarga o una escritura que falla ya no deja un archivo `.varsto-tmp-…` o `.varsto-upload-…` con parte del contenido. Los archivos que llegan de otro dispositivo conservan la hora de modificación que anotó quien los escribió, en lugar de quedar marcados con el momento en que se descargaron. Las herramientas que se fían de la fecha, una compilación, una fototeca, otra copia de seguridad, dejan de ver como nuevo cada archivo descargado.

## Un dispositivo quitado sigue quitado

Los registros de carpeta, las concesiones y el depósito de un dispositivo quitado cuentan solo hasta el primer número de secuencia que dejó vacío. No puede volver más tarde y llenar ese hueco con un registro antedatado. Un miembro de otra bóveda aplica una retirada que lee en la época de la carpeta. Una carpeta a la que quien quitó el dispositivo no pudo cambiar la clave se vuelve a cifrar con clave nueva en la siguiente sincronización de un propietario que aún tiene la clave. Lo que el dispositivo quitado ya tiene en su propio disco, lo conserva. Eso siempre fue verdad, y lo sigue siendo.

Unirse lee el manifiesto de la organización y toma las épocas de la bóveda y las revocaciones solo de sus administradores. Una revocación escrita por un miembro ordinario de la lista ya no abre la bóveda para un dispositivo que se está uniendo.

La línea del registro de actividad que dice que este dispositivo no tiene ninguna clave tiene el mismo botón que la fila de la carpeta, así que un teléfono puede pedir acceso desde esa línea en lugar de buscar la carpeta. El espejo de restic, y las carpetas acopladas debajo, se crean de modo que solo este usuario pueda leerlos.

## El nombre del icono

Los identificadores de la aplicación son ahora `net.varsto.app` en Android y en macOS, `net.varsto.app.ios` en iOS, y `net.varsto.app.alpha` para la compilación de macOS sin firmar. Una aplicación que ya está instalada conserva su identificador anterior, y su bóveda no se mueve, hasta que la instales de nuevo. Instalar el paquete nuevo al lado del antiguo no lo sustituye.

## Si estás en alpha.16

Actualiza cuando quieras. Las dos versiones pueden compartir una bóveda mientras lo haces. Nada en esta publicación te pide que hagas un reset, que imprimas un kit nuevo ni que desinstales una compilación de Android que ya sea la firmada para la publicación de alpha.16. Si una solicitud de uso compartido o una de organización sigue en un archivo en claro de alpha.16, el siguiente comando que la lea la sella. Esto sigue siendo una alfa.
