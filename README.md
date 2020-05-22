# VulnFeed 2 Tenb

VulnFeed 2 Tenb is a way to parse vulnerability data from Cyber Advisory Feeds into Tenable.sc.

This is not supported by Tenable.

## Installation

### Docker Image

Use the pre-built docker image

```bash
docker pull tecnobabble/vulnfeed_2_tenb:latest
```

### Manually Build Docker Image

1. Clone the GitHub repository to an empty folder on your local machine:
```bash
git clone https://github.com/tecnobabble/vulnfeed_2_tenb.git .
```
2. Build the container
```bash
docker build -t vulnfeed_2_tenb .
```

### Local Configuration
Setup your local .env file with the appropriate tenable.sc attributes (replace the attributes below with the ones specific to your environment).

```bash
SC_ADDRESS=10.0.0.102
SC_ACCESS_KEY=89b0aa234237ec13b06da8283919c0f7
SC_SECRET_KEY=8360bf971eb9a1e488d294d830a24eba
SC_PORT=8443
```

#### Notes:
* SC_ADDRESS can be an IP or hostname
* SC_PORT is optional
* The user who's API keys you select should be a part of the same primary group as your main users. No specific user role is needed for this user, as any user can create queries or view plugin data.
* T.sc 5.13 or higher is required [API key usage](https://docs.tenable.com/tenablesc/Content/GenerateAPIKey.htm)

## Usage

Run the container, passing your .env file to the container and specify the feed you want to use.
```bash
$docker run --env-file .env vulnfeed_2_tenb --feed us-cert # queries us-cert alerts and adds appropriate ones to T.sc
Created a query for AA20-133A: Top 10 Routinely Exploited Vulnerabilities
Created a query for AA20-126A: APT Groups Target Healthcare and Essential Services
No CVEs listed in article: AA20-120A: Microsoft Office 365 Security Recommendations skipping.
There is an existing query for AA20-107A: Continued Threat Actor Exploitation Post Pulse Secure VPN Patching skipping.
No CVEs listed in article: AA20-106A: Guidance on the North Korean Cyber Threat skipping.
There is an existing query for AA20-099A: COVID-19 Exploited by Malicious Cyber Actors skipping.
No CVEs listed in article: AA20-073A: Enterprise VPN Security skipping.
No CVEs listed in article: AA20-049A: Ransomware Impacting Pipeline Operations skipping.
There is an existing query for AA20-031A: Detecting Citrix CVE-2019-19781 skipping.
There is an existing query for AA20-020A: Critical Vulnerability in Citrix Application Delivery Controller, Gateway, and SD-WAN WANOP skipping.
```
![example vulnfeed_output](https://res.cloudinary.com/salted-security/image/upload/v1590183891/vulnfeed_output_kj9bqt.png)

### Supported Feeds
* [MS-ISAC](https://www.cisecurity.org/resources/advisory/?o=ms-isac&type=advisory) and [CIS](https://www.cisecurity.org/resources/advisory/?o=ms-isac&type=advisory)
    * Note, this is the same feed; you can specify either for different labels in Tenable.sc
* [US-CERT](https://www.us-cert.gov/ncas/alerts)
* [ICS-CERT](https://www.us-cert.gov/ics/advisories)
* [CERT](https://www.kb.cert.org/vuls/)

### Suggested operations
* Run the script on a scheduled basis; daily is likely frequently enough. The script checks for and should not create duplicates.
* Run the script multiple times with different feeds specified to get multiple feeds into Tenable.sc.

### Basic workflow under the hood
1. Script is called and a feed is specified
2. RSS of the specified feed is pulled, and relevant CVE data is pulled from all recent entries
3. If no CVEs are discarded in the feed, the entry is discarded.
4. Tenable.sc is queried to see if detection exists for the CVEs listed in the entry, if no detection, the entry is discarded.
5. Tenable.sc is queried to see if a Query already exists, if so, the entry is skipped.
6. A Query is created with the feed title and CVEs as filters.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please open a new issue to request support for new feeds.

## License
[GNU GPL](https://choosealicense.com/licenses/gpl-3.0/)
