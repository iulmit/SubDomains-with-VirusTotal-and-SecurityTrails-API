"use strict";

const  FS               = require("fs")
      ,PATH             = require("path")
      ,URL              = require("url")
      ,EXEC_FILE_SYNC   = require("child_process").execFileSync
      
      ,NATURAL_COMPARE  = function(a,b){var ax=[],bx=[]; if("function"===typeof NATURAL_COMPARE.extraction_rule){a=NATURAL_COMPARE.extraction_rule(a); b=NATURAL_COMPARE.extraction_rule(b);} a.replace(/(\d+)|(\D+)/g,function(_,$1,$2){ax.push([$1||Infinity,$2||""]);}); b.replace(/(\d+)|(\D+)/g,function(_,$1,$2){bx.push([$1||Infinity,$2||""]);}); while(ax.length>0 && bx.length>0){var an,bn,nn; an=ax.shift(); bn=bx.shift(); nn=(an[0]-bn[0])||an[1].localeCompare(bn[1]); if(nn) return nn;} return (ax.length-bx.length);} 
      ,RESOLVE          = function(path){path=path.replace(/\"/g,"").replace(/\\+/g,"/"); path=PATH.resolve(path); path=path.replace(/[\\\/]+/g,"/").replace(/\/+$/g,""); return path;} //normalize to Unix-slash (will work on Windows too).
      ,READ             = function(path){return FS.readFileSync(RESOLVE(path),{encoding: "utf8"}).replace(/\r/g,"").split("\n").shift();} //reads all the file-content, return just the first-line.
      ,HEADERS          = {"DNT":             "1"
                          ,"Accept":          "*/*"
                          ,"Referer":         "https://www.virustotal.com/"
                          ,"Connection":      "Close"
                          ,"User-Agent":      "Mozilla/5.0 Chrome"
                          ,"Accept-Language": "en-US,en;q=0.9"
                          ,"Cache-Control":   "no-cache"
                          ,"Pragma":          "no-cache"
                          ,"X-Hello":         "Goodbye"
                          }
      ,GET              = function(url, onresponse, onheaders, onerror){ //supports both headers and request body handling.
                            var HTTP  = require("http")
                               ,HTTPS = require("https")
                               ;
                            
                            url = URL.parse(url);

                            process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
                            
                            const CONF = {protocol           : url.protocol  // "http:" or "https:"
                                         ,auth               : url.auth      // "username:password"
                                         ,hostname           : url.hostname  // "www.example.com"
                                         ,port               : url.port      // 80 or 443
                                         ,path               : url.path      // "/"
                                         ,family             : 4             // IPv4
                                         ,method             : "GET"         // "GET"|"POST"|"HEAD"
                                         ,headers            : HEADERS       //
                                         ,timeout            : 10 * 1000     // 10 seconds
                                         ,agent              : undefined     // use http.globalAgent for this host and port.
                                         ,rejectUnauthorized : false
                                         ,requestCert        : false
                                         }
                                 ,REQUEST = (/https/i.test(url.protocol) ? HTTPS : HTTP).request(CONF)
                                 ,CONTENT = []
                                 ;
                            REQUEST.setSocketKeepAlive(false);                                      //make sure to return right away (single connection mode).
                            REQUEST.on("response", function(response){
                              if("function" === typeof onheaders) onheaders(REQUEST,response,URL,CONTENT.join("")); //response headers.
                              if("function" === typeof onresponse){
                                response.setEncoding("utf8");
                                response.on("data", function(chunk){ CONTENT.push(chunk);                                  } );
                                response.on("end",  function(){      onresponse(CONTENT.join(""), URL, REQUEST, response); } );  //response body.
                              }
                            });
                            REQUEST.on("error", function(error){ onerror(error); });

                            REQUEST.end();
                          }



      ,HOSTNAME = process.argv.filter(function(s){return false === /node\.exe/i.test(s) && process.mainModule.filename !== s;}).pop()
               || EXEC_FILE_SYNC(RESOLVE(__dirname + "/bin/input2stdout.exe"),["SubDomains-Query"],{"encoding":"utf8","timeout":60*1000})
               || ""
      
      ,FILE_OUT = RESOLVE(process.env["TEMP"] || process.env["TMP"] || __dirname) + "/subdomains__" + HOSTNAME + ".txt"

      ,PATH_OF_APIKEY_FILES          = __dirname
      ,CONTENT_APIKEY_VIRUSTOTAL     = READ(PATH_OF_APIKEY_FILES + "/API_VIRUSTOTAL.txt").trim()
      ,CONTENT_APIKEY_SECURITYTRAILS = READ(PATH_OF_APIKEY_FILES + "/API_SECURITYTRAILS.txt").trim()

                                                                                  //example.com --- {"subdomains": ["api.example.com","www.example.com"], "domain_siblings": ["www.example.co.il"]}
      ,URL_VIRUSTOTAL_ALL            = "https://www.virustotal.com/vtapi/v2/domain/report" + "?domain=" + HOSTNAME + "&apikey=" + CONTENT_APIKEY_VIRUSTOTAL

                                                                                 //subdomains   --- example.com --- {"subdomains": ["api","www"]}  --- NOTE: YOU NEED TO CONCAT EACH OF THOSE WITH THE DOMAIN-PART OF THE HOSTNAME TO GET FULL SUBDOMAIN.
                                                                                 //associated   --- collect all of 'records[0..n].hostname' to get domain-siblings           google.com --- {  "records": [    {      "whois": {        "registrar": "MarkMonitor Inc.",        "expiresDate": 1518671592000,        "createdDate": 1108444392000      },      "mail_provider": [        "Google Inc."      ],      "hostname": "youtube.com",      "host_provider": [        "Google Inc."      ],      "computed": {        "company_name": "Google Inc."      },      "alexa_rank": 2    },    {      "whois": {        "registrar": "MarkMonitor Inc. (R84-AFIN)",        "expiresDate": 1498226553000,        "createdDate": 1056376953000      },      "mail_provider": [        "Google Inc."      ],      "hostname": "google.co.in",      "host_provider": [        "Google Inc."      ],      "computed": {        "company_name": "Google Inc."      },      "alexa_rank": 7    },    {      "whois": {        "registrar": null,        "expiresDate": null,        "createdDate": null      },      "mail_provider": [        "Google Inc."      ],      "hostname": "google.de",      "host_provider": [        "Google Inc."      ],      "computed": {        "company_name": null      },      "alexa_rank": 23    }  ],  "record_count": 3,  "meta": {    "total_pages": 1,    "query": "whois_email = 'dns-admin@google.com'",    "page": 1,    "max_page": 100  },  "endpoint": "/v1/domain/google.com/associated"}
      ,URL_SECURITYTRAILS_SUBDOMAINS = "https://api.securitytrails.com/v1/domain/" + HOSTNAME + "/subdomains" + "?apikey=" + CONTENT_APIKEY_SECURITYTRAILS
/* //not availble for free subscription.
      ,URL_SECURITYTRAILS_ASSOCIATED = "https://api.securitytrails.com/v1/domain/" + HOSTNAME + "/associated" + "?apikey=" + CONTENT_APIKEY_SECURITYTRAILS
*/
      ;



var   everything                          = []
     ,done_flag_virustotal                = false
     ,done_flag_securitytrails_subdomains = false
/* //not availble for free subscription.
     ,done_flag_securitytrails_associated = false
*/
     ;



/* ------------------------------------------------------------------------------------- */



if("" === HOSTNAME){
  console.error("[ERROR] missing an hostname (domain) to query about.");
  process.exitCode=333;
  process.exit();
}



NATURAL_COMPARE.extraction_rule = function(s){return s.split(".").reverse().join(".");};  //sort (right-to-left) first super-domain (com,co.il,co.uk,..) then domain (google,youtube,...) then subdomain (api,www,cdn) --- easy to spot groups (subdomains vs. domain-siblings).



function done_handler(){
  if(false === done_flag_virustotal){                console.error("[INFO] request not done yet - VirusTotal");                  return; }
/* //not availble for free subscription.
  if(false === done_flag_securitytrails_subdomains){ console.error("[INFO] request not done yet - SecurityTrails(subdomains)");  return; }
  if(false === done_flag_securitytrails_associated){ console.error("[INFO] request not done yet - SecurityTrails(associated)");  return; }
*/

  everything = everything.sort(NATURAL_COMPARE)
                         .join("\r\n")
                         ;

  console.error("");
  console.error("[INFO] done_handler - output was written to the following external-file:");
  console.error(FILE_OUT);
  FS.writeFileSync(FILE_OUT, everything, {flag:"w", encoding:"utf8"}); //overwrite

  EXEC_FILE_SYNC(RESOLVE(__dirname + "/bin/Notepad2.exe"),[FILE_OUT],{"encoding":"utf8"});
  
  console.error("");
  console.error("[INFO] program is done.");
  process.exitCode=0;
  process.exit();
}



if(CONTENT_APIKEY_VIRUSTOTAL.length > 0){
  console.error("[INFO] request started - VirusTotal [" + URL_VIRUSTOTAL_ALL + "]");
  GET(URL_VIRUSTOTAL_ALL
     ,function(content, url, request, response){




        done_flag_virustotal = true;
        if(200 !== response.statusCode){console.error("[ERROR] request failed (response code [" + response.statusCode + "]) - VirusTotal"); done_handler(); return;}
        console.error("[INFO] request done - VirusTotal");

        try{
        //FS.writeFileSync("debug__content_as_is.txt", content, {flag:"w", encoding:"utf8"}); //overwrite
        content = JSON.parse(content);
        //FS.writeFileSync("debug__content_parsed_as_json.json", JSON.stringify(content,null,2).replace(/,\n /gm, "\n ,").replace(/ *(,(\ +))/gm, "$2,"), {flag:"w", encoding:"utf8"}); //overwrite
        }catch(err){ console.error("[INFO] can not parse content as JSON - VirusTotal",content); }
        
        if("undefined" === typeof content.domain_siblings
        && "undefined" === typeof content.subdomains){
          console.error('[INFO] can not extract \".subdomains\" or \".domain_siblings\" from the JSON, this means the entries are not existing in the JSON due to empty result, or the API for VirusTotal has changed!');
        }
        everything = everything.concat(content.domain_siblings || [], content.subdomains || []);
        console.error("[INFO] collected subdomains: [" + everything.length + "]");
        done_handler();
      }
     ,undefined
     ,function(){done_flag_virustotal=true; console.error("[ERROR] request failed (request error) - VirusTotal"); done_handler();}
  );
}

/*
if(CONTENT_APIKEY_SECURITYTRAILS.length > 0){
  console.error("[INFO] request started - SecurityTrails(subdomains) [" + URL_SECURITYTRAILS_SUBDOMAINS + "]");
  GET(URL_SECURITYTRAILS_SUBDOMAINS
     ,function(content, url, request, response){
        done_flag_securitytrails_subdomains = true;
        if(200 !== response.statusCode){console.error("[ERROR] request failed (response code [" + response.statusCode + "]) - SecurityTrails(subdomains)"); done_handler(); return;}
        console.error("[INFO] request done - SecurityTrails(subdomains)");

        content = JSON.parse(content);
        everything = everything.concat(  (content.subdomains || [])
                                           .map(function(partial_subdomain){return partial_subdomain + "." + HOSTNAME;})
                                      );
        console.error("[INFO] collected subdomains: [" + everything.length + "]");
        done_handler();
      }
     ,undefined
     ,function(){done_flag_securitytrails_subdomains=true; console.error("[ERROR] request failed (request error) - SecurityTrails(subdomains)"); done_handler();}
  );

/* //not availble for free subscription.
  console.error("[INFO] request started - SecurityTrails(associated) [" + URL_SECURITYTRAILS_ASSOCIATED + "]");
  GET(URL_SECURITYTRAILS_ASSOCIATED
     ,function(content, url, request, response){
        done_flag_securitytrails_associated = true;
        if(200 !== response.statusCode){console.error("[ERROR] request failed (response code [" + response.statusCode + "]) - SecurityTrails(associated)"); done_handler(); return;}
        console.error("[INFO] request done - SecurityTrails(associated)");

        content = JSON.parse(content);
        everything = everything.concat(  (content.records || [])
                                           .map(function(record){return record.hostname || ""}).filter(function(s){return s.length > 3})
                                      );
        console.error("[INFO] collected subdomains: [" + everything.length + "]");
        done_handler();
      }
     ,undefined
     ,function(){done_flag_securitytrails_associated=true; console.error("[ERROR] request failed (request error) - SecurityTrails(associated)"); done_handler();}
  );
}

*/