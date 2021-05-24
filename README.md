//yarn add pug --ignore-engines

# Data to be provided

```.env
DB_URI='db'

LOGIN_MAIL_USERNAME='mail@example.com'
LOGIN_MAIL_PASSWORD='password'
FROM_NAME='Example Login'
FROM_MAIL_ADDRESS="login@example.com"
MAIL_HOST='mail.example.com'
REPLY_TO='mail@example.com'
MAIL_AGENT='Sugar-Free-Mail-2020'

WEB_SCHEMA='http' //defaults to https

WEB_URI='localhost'

VERBOSE_WEB_RESPONSES=true
MAGIC_LINK_EXPIRE_MINUTES=10
REQUEST_NEW_MAGIC_LINK_MINUTES=0.5


IP_REQUEST_TIME_MINUTES=10
IP_REQUEST_PER_TIME=100
```

# functions

## login via mail

mail adresse an die der login code geschickt werden soll wird angegeben:

-   gleiche adresse wird mehrmals in kurzer zeit eingegeben
    -   mail server dos
    -   empfänger der mail bekommt jede menge ungewollter mail
    -   mail server wird als spam server markiert

-> senden einer mail an eine adresse verzögern z.b. nur alle 30 sec. erlauben
-> möglichkeit des denial of service an einem account durch permanentes requesten von login codes

-> senden von mails an beliebige personen
-> einer ip nur erlauben 3 verschiedene mail adressen einzugeben für z.b. 1h
-> denial of service z.b. in uni netzwerken durch permanentes senden von mails
-> slowdown nicht per mail adresse sonder per ip adresse um das spammen von adressen zu verhindern

-> slowdown pro mail und pro ip adresse falls der angreifer viele verschiedene verwendet
-> funktioniert nicht wenn ein ipv6 subnet verwendet wird

**-> slowdown des ganzen ipv6 subnets oder der ganzen ipv4 adresse und slowdown der eingegebenen mail adresse**
**-> bei einem erfolgreichen login ein jwt für diesen account setzen welches verifiziert dass der user sich schonmal erfolgreich angemeldet hat in diesem fall wird das obere verfahren weniger wichtig gewertet**

wichtige accountverändernde sachen und csrf
**high security token ausstellen für welches man sich nochmal authentifizieren muss; nur mit diesem token sind wichtigere änderungen möglich; dieses token hat eine deutlich kürzere lebenszeit wird aber auch bei jedem normalen login ausgestellt damit man sich nie zwei mal direkt nacheinander anmelden muss**

**nur post request**
**nur cookies mit allen sicherheitsattributen**
**alle cors und andere header bei allen anfragen**

**bestehende 2fa kann nur mit korrektem bestehenden 2fa code geändert werden**

**origin checken**

ip rate limits werden angewendet
FUNKTIONIERT MIT REVERSE PROXY?
um im zweifelsfall dos zu verhindern alternative methode um einen magic link anzufordern
zusätzlicher request magic link in jeder magic link mail
