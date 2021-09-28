grab subdomains and domain-siblings for entered domain using VirusTotal and SecurityTrail online-API and NodeJS.

API used:
<pre>
*** available for free users: *** 
https://www.virustotal.com/vtapi/v2/domain/report?domain=<strong>HOSTNAME</strong>&apikey=<strong>KEY</strong>
https://api.securitytrails.com/v1/domain/<strong>HOSTNAME</strong>/subdomains?apikey=<strong>KEY</strong>

*** not for free users: *** 
https://api.securitytrails.com/v1/domain/<strong>HOSTNAME</strong>/associated?apikey=<strong>KEY</strong>
</pre>

<hr/>

first time usage: rename (or copy) the '.txt.example' files to just '.txt' and put your API key in each, you can leave API_SECURITYTRAILS.txt empty since its API sucks so I've commented-out the main functionality in the index.js regarding it anyway.

<hr/>

changelog is available in  
<a href="https://github.com/eladkarako/SubDomains-with-VirusTotal-and-SecurityTrails-API/commits">https://github.com/eladkarako/SubDomains-with-VirusTotal-and-SecurityTrails-API/commits</a>  
and changelog.nfo (with some additional information, and "versions" are date based of the commit).
