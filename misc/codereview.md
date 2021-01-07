Code Review Tools
General

https://www.sonarqube.org/downloads/
https://deepsource.io/signup/
https://github.com/pyupio/safety
https://github.com/returntocorp/semgrep
https://github.com/WhaleShark-Team/cobra
​
# Find interesting strings
https://github.com/s0md3v/hardcodes
https://github.com/micha3lb3n/SourceWolf
https://libraries.io/pypi/detect-secrets

JavaScript

https://jshint.com/
https://github.com/jshint/jshint/

NodeJS

https://github.com/ajinabraham/nodejsscan

Electron

https://github.com/doyensec/electronegativity

Python

# bandit
https://github.com/PyCQA/bandit
# pyt
https://github.com/python-security/pyt

.NET

# dnSpy
https://github.com/0xd4d/dnSpy
​
# .NET compilation
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe test.cs

Java

# JD-Gui
https://github.com/java-decompiler/jd-gui
​
# Java compilation step-by-step
javac -source 1.8 -target 1.8 test.java
mkdir META-INF
echo "Main-Class: test" > META-INF/MANIFEST.MF
jar cmvf META-INF/MANIFEST.MF test.jar test.class

Task
	

Command

Execute Jar
	

java -jar [jar]

Unzip Jar
	

unzip -d [output directory] [jar]

Create Jar
	

jar -cmf META-INF/MANIFEST.MF [output jar] *

Base64 SHA256
	

sha256sum [file] | cut -d' ' -f1 | xxd -r -p | base64

Remove Signing
	

rm META-INF/.SF META-INF/.RSA META-INF/*.DSA

Delete from Jar
	

zip -d [jar] [file to remove]

Decompile class
	

procyon -o . [path to class]

Decompile Jar
	

procyon -jar [jar] -o [output directory]

Compile class
	

javac [path to .java file]

