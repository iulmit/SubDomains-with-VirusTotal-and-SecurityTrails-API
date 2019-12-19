grab subdomains and domain-siblings for entered domain using VirusTotal and SecurityTrail online-API and NodeJS.

API used:
<pre>
*** available for free users: *** 
https://www.virustotal.com/vtapi/v2/domain/report?domain=<strong>HOSTNAME</strong>&apikey=<strong>KEY</strong>
https://api.securitytrails.com/v1/domain/<strong>HOSTNAME</strong>/subdomains?apikey=<strong>KEY</strong>

*** not for free users: *** 
https://api.securitytrails.com/v1/domain/<strong>HOSTNAME</strong>/associated?apikey=<strong>KEY</strong>
</pre>
