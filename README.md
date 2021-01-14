
# VulnFeed 2 Tenb

VulnFeed 2 Tenb is a way to parse vulnerability data from Cyber Advisory Feeds into [Tenable.sc](https://www.tenable.com/products/tenable-sc).

Integrate [Tenable.sc](https://www.tenable.com/products/tenable-sc) with any of the supported Cyber Advisory Organizational feeds (US-CERT, MS-ISAC, CIS, CERT, etc) to automatically pull in advisory alerts, rather than manually copying/pasting them in. If the advisory contains a CVE, a query will be created within Tenable.sc with the name of the advisory (ex: Multiple Vulnerabilities in Google Chrome) that can seen, prioritized, and reported on by the Tenable user.  Alerts, Assets, Assurance Report Cards, and Reports can also be created automatically.

***This tool is not an officially supported Tenable project***

***Use of this tool is subject to the terms and conditions identified below, and is not subject to any license agreement you may have with Tenable***

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

#### Configuration Notes:
* SC_ADDRESS can be an IP or hostname.
* SC_PORT is optional; defaults to 443.
* The user who's API keys you select should be a part of the same primary group as the user who will use the objects created, though objects can be shared to other groups. 
* The user must be able to create alerts, if the `--alert` flag is used, otherwise no specific user role is needed for this user, as any user can create queries, assets, dashboards, and reports or view plugin attribute data.
* If desired to be used in multiple organizations within one [Tenable.sc](https://www.tenable.com/products/tenable-sc) console, run the script multiple times, specifiying different API keys for a user in each organization.

## Requirements
* [Tenable.sc](https://www.tenable.com/products/tenable-sc) 5.13 or higher is required for [API key usage](https://docs.tenable.com/tenablesc/Content/GenerateAPIKey.htm)
* Docker; though technically you can run the script standalone (not supported).
* Internet access for the container to access the RSS feed of the cyber threat feed you're grabbing
* Network access to your T.sc instance over the UI/API interface (default is TCP 443)

## Usage

Run the container, passing your .env file to the container and specify the feed you want to use, plus any additional content generation.

### Flags
 - `--feed`
	 - Generates a query based on the CVEs noted in the feed entry. 
	 - See the supported feeds below. 
		 * [MS-ISAC](https://www.cisecurity.org/resources/advisory/?o=ms-isac&type=advisory) and [CIS](https://www.cisecurity.org/resources/advisory/?o=ms-isac&type=advisory)
           * Note, this is the same feed; you can specify either for different labels in Tenable.sc
        * [US-CERT](https://www.us-cert.gov/ncas/alerts)  
        * [ICS-CERT](https://www.us-cert.gov/ics/advisories)   
        * [CERT](https://www.kb.cert.org/vuls/)   
        * [TENABLE](https://www.tenable.com/blog/cyber-exposure-alerts)
	 - Takes 1 string argument; required.  
 -  `--asset`
	 - Creates a dynamic asset in Tenable.sc with the CVEs noted in the feed entry.
	 - No arguments, optional.
 - `--report`
	 - Creates an on-demand PDF report in Tenable.sc with the CVEs noted in the feed entry.
	 - No arguments, optional.
 - `--alert`
	 - Creates a weekly alert in Tenable.sc using the query created above.
	 - If specified with the `--report` flag, the alert will generate the report IF any vulnerable instances are found.
	 - No arguments, optional.
 - `--email`
	 - If specified with the `--report` flag, email targets are added in the report definition. 
	 - If specified with the `--alert` flag (and no `--report` flag), the alert will generate an email to the specified addresses, including the scan results.
	 - If specified without either the `--report` or `--alert` flag, this has no impact.
	 - Multiple emails can be comma separated and encased in quotes.
	 - Takes 1 string argument, optional.
 - `--arc`
	 - Creates an Assurance Report Card for the Feed and a Policy Statement for each feed entry.
	 - No arguments, optional
 - `--dashboard`
         - Creates a Dashboard for each feed entry.
         - No arguments, optional
	 
```
$ docker run --rm --env-file .env tecnobabble/vulnfeed_2_tenb:latest --feed us-cert

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

### Custom Reporting Templates
A default report template is included with the tool. If you want to specify a custom report PDF template, use [Docker Volumes](https://docs.docker.com/storage/volumes/) to specify the `templates/custom_sc_report.xml` file.  NOTE: You must specify the `--report` flag to use custom reporting templates. 
>`$ docker run --rm -v ${PWD}/custom_report_template.xml:templates/custom_sc_report.xml --env-file .env tecnobabble/vulnfeed_2_tenb:latest --feed us-cert --report`

Where *custom_report_template.xml* is the filename of an exported PDF template from [Tenable.sc](https://www.tenable.com/products/tenable-sc) that's on the host running Docker.

### Custom Dashboard Templates
A default dashboard template is included with the tool. If you want to specify a custom dashboard template, use [Docker Volumes](https://docs.docker.com/storage/volumes/) to specify the `templates/custom_sc_dashboard.xml` file.  NOTE: You must specify the `--dashboard` flag to use custom dashboard templates.
>`$ docker run --rm -v ${PWD}/custom_dashboard_template.xml:templates/custom_sc_dashboard.xml --env-file .env tecnobabble/vulnfeed_2_tenb:latest --feed us-cert --dashboard`

Where *custom_dashboard_template.xml* is the filename of an exported dashboard template from [Tenable.sc](https://www.tenable.com/products/tenable-sc) that's on the host running Docker.

You may use the following variables when generting dashboards or reports to use dynamic content from the Vulnerability Feed entry.  As an example, please see the template included at `templates/sc_template.xml`
 - **{{ Feed }}**
     - Name of the feed being called, in uppercase. Ex: US-CERT
 - **{{ Entry_Title }}**
     - Title of the feed entry
 - **{{ Entry_ShortDesc }}**
     - The following text: 
         For more information, please see the full page at *{url_to_full_entry_page}*
 - **{{ Entry_Summary }}**
     - The first 500 characters of the entry description.
 - **CVE-1990-0000**
     - This will serve as a placeholder for any CVEs listed in each feed entry. 

### Suggested operations
* Run the script on a scheduled basis; daily is likely frequently enough. The script checks for and should not create duplicates.
* Run the docker container with the `--rm` flag to auto delete the container after running.
* If an advisory is released that specifies vulnerabilities that do not yet have published plugins, the script will check for and create a query when plugins do exist, as long as the advisory is still recent enough to be in the feed.
* Run the script multiple times with different feeds specified to get multiple feeds into Tenable.sc.
* Generated alerts currently will run on a weekly schedule, Mondays at 7 AM EST.  
* All queries, assets, reports, and alerts can be edited after generation by the Tenable.sc user.  If the object name is changed, the script may generate a new object with the original name.

### Basic workflow under the hood
1. Script is called and a feed is specified
2. RSS of the specified feed is pulled, and relevant CVE data is pulled from all recent entries
3. If no CVEs are discarded in the feed, the entry is discarded.
4. Tenable.sc is queried to see if detection exists for the CVEs listed in the entry, if no detection, the entry is discarded.
5. Tenable.sc is queried to see if a Query already exists, if so, the entry is skipped.
6. A Query is created with the feed title and CVEs as filters.
7. If additional objects are requested (assets, reports, or alerts), they are created.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please open a new issue to request support for new feeds.

## License
[GNU GPL](https://choosealicense.com/licenses/gpl-3.0/)
