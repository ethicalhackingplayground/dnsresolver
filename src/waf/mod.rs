// Importing the `Duration` struct from the `time` module in the `std` crate.
use std::time::Duration;

// Importing the `Regex` struct from the `regex` crate.
use regex::Regex;

// Importing the `redirect` function from the `reqwest` crate.
use reqwest::{redirect, Request};

// Importing the `Value` enum from the `serde_json` crate.
use serde_json::Value;

// This code block defines a constant variable named `WAF_SIGS` of type `&str`.
// The value of `WAF_SIGS` is a raw string literal that starts with `r#"` and ends with `"`.
// Raw string literals allow us to include special characters like backslashes without escaping them.
// The purpose of this constant is not clear from this code block.
// Please provide more context or code if you need further assistance.
const WAF_SIGS: &str = r#"
[
 {
   "WAF_NAME": "360WangZhanBao",
   "KEYWORD": "X-Powered-By-360WZB",
   "REGEX": "^X-Powered-By-360WZB",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "360WangZhanBao"
 },
 {
   "WAF_NAME": "Akamai",
   "KEYWORD": "ak_bmsc",
   "REGEX": "^Set-Cookie: ak_bmsc=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://community.akamai.com",
   "DESCRIPTION": "Akamai Global Host (aka Edge Server, Edge node)"
 },
 {
   "WAF_NAME": "Akamai",
   "KEYWORD": "AkamaiGHost",
   "REGEX": "^Server: AkamaiGHost",
   "HEADER_ONLY": true,
   "REFERENCE": "https://community.akamai.com",
   "DESCRIPTION": "Akamai Global Host (aka Edge Server, Edge node)"
 },
 {
   "WAF_NAME": "Anquanbao",
   "KEYWORD": "X-Powered-By-Anquanbao",
   "REGEX": "^X-Powered-By-Anquanbao",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Anquanbao"
 },
 {
   "WAF_NAME": "Barracuda WAF",
   "KEYWORD": "BNI__BARRACUDA_LB_COOKIE",
   "REGEX": "^Set-Cookie: BNI__BARRACUDA_LB_COOKIE=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Barracuda App Firewall"
 },
 {
   "WAF_NAME": "Barracuda WAF",
   "KEYWORD": "BNI_persistence",
   "REGEX": "^Set-Cookie: BNI_persistence=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Barracuda App Firewall"
 },
 {
   "WAF_NAME": "BinarySec",
   "KEYWORD": "BinarySec",
   "REGEX": "^Server: BinarySec",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "BinarySec"
 },
 {
   "WAF_NAME": "BinarySec",
   "KEYWORD": "x-binarysec-via",
   "REGEX": "^x-binarysec-via",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "BinarySec"
 },
 {
   "WAF_NAME": "BinarySec",
   "KEYWORD": "x-binarysec-nocache",
   "REGEX": "^x-binarysec-nocache",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "BinarySec"
 },
 {
   "WAF_NAME": "ChinaCache",
   "KEYWORD": "ChinaCache",
   "REGEX": "^Powered-By-ChinaCache",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "ChinaCache CDN"
 },
 {
   "WAF_NAME": "Cisco ACE XML",
   "KEYWORD": "Server: ACE XML Gateway",
   "REGEX": "^Server: ACE XML Gateway",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Cisco ACE XML Gateway"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "ns_af",
   "REGEX": "^Set-Cookie: ns_af=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "citrix_ns_id",
   "REGEX": "^Set-Cookie: citrix_ns_id",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "NSC_",
   "REGEX": "^Set-Cookie: NSC_",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "Cneonction",
   "REGEX": "^Cneonction: close",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "Coection",
   "REGEX": "^NnCoection: close",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "NS-CACHE",
   "REGEX": "^Via: NS-CACHE",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "X-client-ip",
   "REGEX": "^X-client-ip",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Citrix NetScaler",
   "KEYWORD": "pwcount",
   "REGEX": "^Set-Cookie: pwcount",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Citrix NetScaler"
 },
 {
   "WAF_NAME": "Cloudflare",
   "KEYWORD": "cloudflare-nginx",
   "REGEX": "^Server: cloudflare-nginx",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Cloud flare"
 },
 {
   "WAF_NAME": "Cloudflare",
   "KEYWORD": "__cfduid",
   "REGEX": "^Set-Cookie: __cfduid",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Cloud flare"
 },
 {
   "WAF_NAME": "Cloudflare",
   "KEYWORD": "cloudflare",
   "REGEX": "^Server: cloudflare",
   "HEADER_ONLY": true,
   "REFERENCE": "https://www.cloudflare.com",
   "DESCRIPTION": "Cloud-based CDN, WAF & DDoS prevention"
 },
 {
   "WAF_NAME": "DotDefender",
   "KEYWORD": "X-dotDefender",
   "REGEX": "^X-dotDefender",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Applicure dotDefender"
 },
 {
   "WAF_NAME": "F5 Big-IP",
   "KEYWORD": "BIG-IP-F5",
   "REGEX": "^Set-Cookie: BIG-IP-F5",
   "HEADER_ONLY": true,
   "REFERENCE": "https://support.f5.com",
   "DESCRIPTION": "F5 WAF & DDoS prevention"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "MRHSession",
   "REGEX": "^Set-Cookie: MRHSession",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "BigIP",
   "REGEX": "^Server: BigIP",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "BIG-IP",
   "REGEX": "^Server: BIG-IP",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "BIGIP",
   "REGEX": "^Server: BIGIP",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "F5_ST",
   "REGEX": "^Set-Cookie: F5_ST",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "F5_HT",
   "REGEX": "^Set-Cookie: F5_HT",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "LastMRH_Session",
   "REGEX": "^Set-Cookie: LastMRH_Session",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "MRHSequence",
   "REGEX": "^Set-Cookie: MRHSequence",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP APM",
   "KEYWORD": "MRHSHint",
   "REGEX": "^Set-Cookie: MRHSHint",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 BIG-IP APM"
 },
 {
   "WAF_NAME": "F5 Big-IP ASM",
   "KEYWORD": "Set-Cookie: TS",
   "REGEX": "^Set-Cookie: TS[a-zA-Z0-9]{3,8}",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Big-IP ASM"
 },
 {
   "WAF_NAME": "F5 Big-IP LTM",
   "KEYWORD": "BIGipServer",
   "REGEX": "^Set-Cookie: BIGipServer",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Big-IP LTM"
 },
 {
   "WAF_NAME": "F5 Firepass",
   "KEYWORD": "uRoamTestCookie",
   "REGEX": "^Set-Cookie: uRoamTestCookie",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Firepass"
 },
 {
   "WAF_NAME": "F5 Firepass",
   "KEYWORD": "MRHCId",
   "REGEX": "^Set-Cookie: MRHCId",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Firepass"
 },
 {
   "WAF_NAME": "F5 Firepass",
   "KEYWORD": "uRoamTestCookie",
   "REGEX": "^Set-Cookie: uRoamTestCookie",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Firepass"
 },
 {
   "WAF_NAME": "F5 Firepass",
   "KEYWORD": "MRHIntranetSession",
   "REGEX": "^Set-Cookie: MRHIntranetSession",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 Firepass"
 },
 {
   "WAF_NAME": "F5 TrafficShield",
   "KEYWORD": "F5-TrafficShield",
   "REGEX": "^Server: F5-TrafficShield",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "F5 TrafficShield"
 },
 {
   "WAF_NAME": "HyperGuard",
   "KEYWORD": "WODSESSION",
   "REGEX": "^Set-Cookier: WODSESSION=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Art of Defence HyperGuard"
 },
 {
   "WAF_NAME": "IBM DataPower",
   "KEYWORD": "X-Backside-Transport",
   "REGEX": "^X-Backside-Transport",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "IBM DataPower"
 },
 {
   "WAF_NAME": "Incapsula CDN",
   "KEYWORD": "X-CDN: Incapsula",
   "REGEX": "^X-CDN: Incapsula",
   "HEADER_ONLY": true,
   "REFERENCE": "https://www.incapsula.com",
   "DESCRIPTION": "Cloud-based CDN, WAF & DDos prevention"
 },
 {
   "WAF_NAME": "Incapsula WAF",
   "KEYWORD": "incap_ses",
   "REGEX": "^Set-Cookie: incap_ses",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Incapsula WAF"
 },
 {
   "WAF_NAME": "Incapsula WAF",
   "KEYWORD": "Set-Cookie: visid",
   "REGEX": "^Set-Cookie: visid",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Incapsula WAF"
 },
 {
   "WAF_NAME": "InfoGuard Airlock",
   "KEYWORD": "Set-Cookie: AL",
   "REGEX": "^Set-Cookie: AL[_-]?(SESS|LB)=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Airlock"
 },
 {
   "WAF_NAME": "MissionControl",
   "KEYWORD": "Server: Mission Control Application Shield",
   "REGEX": "^Server: Mission Control Application Shield",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Mission Control Application Shield"
 },
 {
   "WAF_NAME": "ModSecurity",
   "KEYWORD": "mod_security",
   "REGEX": "^Server: mod_security",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Trustwave ModSecurity"
 },
 {
   "WAF_NAME": "ModSecurity",
   "KEYWORD": "Mod_Security",
   "REGEX": "^Server: Mod_Security",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Trustwave ModSecurity"
 },
 {
   "WAF_NAME": "ModSecurity",
   "KEYWORD": "NOYB",
   "REGEX": "^Server: NOYB",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Trustwave ModSecurity"
 },
 {
   "WAF_NAME": "NetContinuum",
   "KEYWORD": "NCI__SessionId",
   "REGEX": "^Set-Cookie: NCI__SessionId=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "NetContinuum"
 },
 {
   "WAF_NAME": "NSFocus",
   "KEYWORD": "NSFocus",
   "REGEX": "^Server: NSFocus",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "NSFocus"
 },
 {
   "WAF_NAME": "PowerCDN",
   "KEYWORD": "PowerCDN",
   "REGEX": "^Server: PowerCDN",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "PowerCDN"
 },
 {
   "WAF_NAME": "Profense",
   "KEYWORD": "profense",
   "REGEX": "^Server: profense",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Profense"
 },
 {
   "WAF_NAME": "Safedog",
   "KEYWORD": "safedog-flow-item",
   "REGEX": "^Set-Cookie: safedog-flow-item=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Safedog"
 },
 {
   "WAF_NAME": "Safedog",
   "KEYWORD": "Safedog",
   "REGEX": "^Server: Safedog",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Safedog"
 },
 {
   "WAF_NAME": "Teros WAF",
   "KEYWORD": "st8id",
   "REGEX": "^Set-Cookie: st8id=",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "Teros WAF"
 },
 {
   "WAF_NAME": "USP Secure Entry Server",
   "KEYWORD": "Secure Entry Server",
   "REGEX": "^Server: Secure Entry Server",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "USP Secure Entry Server"
 },
 {
   "WAF_NAME": "West263CDN",
   "KEYWORD": "WT263CDN",
   "REGEX": "^X-Cache: .+WT263CDN-.+",
   "HEADER_ONLY": true,
   "REFERENCE": "https://github.com/EnableSecurity/wafw00f/",
   "DESCRIPTION": "West263CDN"
 },
 {
   "WAF_NAME": "ZenEdge Cloud",
   "KEYWORD": "ZENEDGE",
   "REGEX": "^Server: ZENEDGE",
   "HEADER_ONLY": true,
   "REFERENCE": "https://www.zenedge.com",
   "DESCRIPTION": "Cloud-based WAF & DDoS prevention"
 },
 {
   "WAF_NAME": "ZenEdge Cloud",
   "KEYWORD": "Served-By-Zenedge",
   "REGEX": "^X-Cdn: Served-By-Zenedge",
   "HEADER_ONLY": true,
   "REFERENCE": "https://www.zenedge.com",
   "DESCRIPTION": "Cloud-based WAF & DDoS prevention"
 }
]
"#;

pub async fn detect_waf(host: String, request: Request, timeout: usize) -> bool {
    // Parse the string of data into serde_json::Value.
    let signature: Value = match serde_json::from_str(&WAF_SIGS) {
        Ok(v) => v, // If parsing is successful, assign the parsed value to `signature`.
        Err(_) => {
            // If parsing fails, print the error message and return `false`.
            return false;
        }
    };

    // Create a new header map.
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    // Create a new reqwest::Client with custom configurations.
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect::Policy::limited(timeout))
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Execute the request and get the response.
    let response = match client.execute(request).await {
        Ok(r) => r, // If executing the request is successful, assign the response to `response`.
        Err(_) => return false, // If executing the request fails, return `false`.
    };

    let signatures = match signature.as_array() {
        Some(s) => s,
        None => return false, // If executing the request fails, return `false`.
    };

    for sig in signatures {
        // Get the regex pattern from the `signature` value.
        let pattern = match sig["REGEX"].as_str() {
            Some(p) => String::from(format!("(?i){}", p.to_string())), // If the pattern exists, assign it to `pattern`.
            None => "".to_string(), // If the pattern doesn't exist, skip to the next header.
        };

        // Get the headers from the `response` object.
        let headers = response.headers();
        let mut header_str = String::from("");
        for header in headers {
            let header_name = header.0.to_string();
            let header_value = match header.1.to_str() {
                Ok(r) => r.to_string(), // If creating the regex is successful, assign it to `re`.
                Err(_) => "".to_string(), // If creating the regex fails, skip to the next header.
            };

            header_str.push_str(&format!("{}: {}\n", header_name, header_value));
        }

        // Get the WAF name from the `signature` value.
        let waf_name = match sig["WAF_NAME"].as_str() {
            Some(p) => p,         // If the WAF name exists, assign it to `waf_name`.
            None => return false, // If the WAF name doesn't exist, skip to the next header.
        };

        // Create a regular expression object from the pattern.
        let re = match Regex::new(&pattern) {
            Ok(r) => r,             // If creating the regex is successful, assign it to `re`.
            Err(_) => return false, // If creating the regex fails, skip to the next header.
        };

        // Check if the header value matches the regex pattern.
        if re.is_match(&header_str) {
            // Print that a WAF has been detected on the host.
            eprintln!("[+] WAF detected {} on host: {}", waf_name, host);
            return true;
        }
    }

    return false; // If no header matches the regex pattern, return `false`.
}
