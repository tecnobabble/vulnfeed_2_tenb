#!/usr/bin/env python
import feedparser
import re
from tenable.sc import TenableSC
import os
from decouple import config
import getopt, sys
import requests
from jinja2 import Environment, FileSystemLoader
from phpserialize import serialize, unserialize
import base64
import ast
from bs4 import BeautifulSoup

'''
# Set some variables that need setting (pulled from .env file passed to container or seen locally in the same folder as script)
sc_address = config('SC_ADDRESS')
sc_access_key = config('SC_ACCESS_KEY')
sc_secret_key = config('SC_SECRET_KEY')
sc_port = config('SC_PORT', default=443)
'''

# Handle arguments passed to script.  Note Help is defined but not yet supported.
full_cmd_arguments = sys.argv
argument_list = full_cmd_arguments[1:]
short_options = "hfr:"
long_options = ["help", "feed=", "report"]

try:
    arguments, values = getopt.getopt(argument_list, short_options, long_options)
except getopt.error as err:
    # Output error, and return with an error code
    print (str(err))
    sys.exit(2)

#####################
# Most of the code that does the actual work
#####################
'''
# Login to Tenable.sc
sc = TenableSC(sc_address, port=sc_port)
sc.login(access_key=sc_access_key, secret_key=sc_secret_key)

# Pull all existing queries from T.sc that this API user can see.
sc_queries = sc.queries.list()
'''
# Function to de-dupe CVE list.  Basically convert to a dictionary and back to a list.
def de_dup_cve(x):
    return list(dict.fromkeys(x))

# Main function to pull feeds and query tenable
def query_populate(input_url, feed_source):
    feed_url = feedparser.parse(input_url)
    for entry in feed_url.entries:
        # Search through the text of the advisory and pull out any CVEs
        if feed_source == "CERT":
            advisory_cve = cert_search(entry)
        elif feed_source == "ICS-CERT":
            advisory_cve = ics_cert_search(entry)
        elif feed_source == "ACSC":
            advisory_cve = acsc_search(entry)
        else:
            advisory_cve = re.findall("(CVE-\d{4}-\d{1,5})", str(entry.summary_detail))
        # de-dupe any CVEs that are listed multiple times
        cves = de_dup_cve(advisory_cve)
        # If there aren't any, start over on the next article
        if not cves:
            print("No CVEs listed in article:", entry.title, "skipping.")
            continue
        '''    
        # Query To see if plugins exist to test for the vulnerability
        has_plugins = False
        for cve in cves:
            plugins = sc.plugins.list(filter=('xrefs', 'like', cve))
            if any(True for _ in plugins):
                has_plugins = True
                continue
            else:
                continue
        if has_plugins is False:
            print("No detection plugins found for CVEs in", entry.title, "skipping.")
            continue
        for x in range(len(sc_queries['usable'])):
            if entry.title == sc_queries['usable'][x]['name']:
                print("There is an existing query for", entry.title, "skipping.")
                break
        else:
            # Turn the CVEs into a comma list
            cve_s = ', '.join(cves)
            # Create the Query
            query = sc.queries.create(entry.title, 'sumid', 'vuln', ('cveID', '=', cve_s), tags=str(feed_source))
            print("Created a query for", entry.title)
        '''
        if report_request:
            #print(entry.title, entry.link)
            entry_description = entry_parse(entry.summary)
            cve_s = ', '.join(cves)
            gen_report(entry, entry_description, cve_s, feed_source)

# Generate a canned t.sc report about the entry
def gen_report(entry, entry_description, cve_s, feed_source):
    # Set some variables for parsing
    Entry_Title = entry.title
    Entry_URL = "For more information, please see the full page at " + entry.link
    Entry_Summary = entry_description
    cve_list = cve_s
    
    # Let's read the base sc template and pull out the report definition
    sc_template_file = open("templates/sc_template.xml", "r")
    template_contents = sc_template_file.read()
    template_def = re.search("<definition>(.+)</definition>", str(template_contents))
    sc_template_file.close()

    # Let's put the encoded report def into a format we can work with
    template_def = base64.b64decode(template_def.group(1))
    template_def = unserialize(template_def, decode_strings=True)

    # Replace the CVE placeholder with something we can swap out later
    template_def = str(template_def).replace("CVE-1990-0000", "{{ cve_list }}")

    # Write this definition template to a file
    template_def_file = open("templates/definition.txt", "w")
    template_def_file.write(template_def)
    template_def_file.close()

    # Load the definition template as a jinja template
    env = Environment(loader = FileSystemLoader('./templates'), trim_blocks=True, lstrip_blocks=True)
    template_def = env.get_template('definition.txt')

    #Render the definition template with data and print the output
    report_raw = template_def.render(Entry_Title=Entry_Title, Entry_URL=Entry_URL, Entry_Summary=Entry_Summary, cve_list=cve_list)

    # Convert the now rendered template back into a format that tsc can understand (base64 encoded PHP serilaized string)
    report_raw = ast.literal_eval(report_raw)
    report_output = base64.b64encode(serialize(report_raw))

    # Render the full XML report template and write the output to a file that we'll then upload to tsc.
    report = env.get_template('report.txt')
    report_xml = report.render(Entry_Title=Entry_Title, Feed=feed_source, Entry_URL=Entry_URL, report_output=report_output.decode('utf8'))
    report_name = Entry_Title.replace(" ","").replace(":","-")[:15] + "_report.xml"
    generated_tsc_report_file = open(report_name, "w")
    generated_tsc_report_file.write(report_xml)
    generated_tsc_report_file.close()
    
# Get a reasonable summary if one isn't provided
def entry_parse(entry_description):
    entry_description = entry_description.replace("<p>", " ").replace("<br/>"," ").replace("\n","")
    entry_description = BeautifulSoup(entry_description, features="html.parser")
    entry_description = entry_description.text[:500] + (entry_description.text[500:] and '...')
    return entry_description

# CMU CERT doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def cert_search(entry):
    url = re.search("(https://kb.cert.org/vuls/id/\d{3,})", str(entry))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# ICS CERT doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def ics_cert_search(entry):
    url = re.search("(https://www.us-cert.gov/ics/advisories/icsa-[\d-]{5,10})", str(entry))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# ACSC doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def acsc_search(entry):
    url = re.search("(https://www.cyber.gov.au/threats/.+)", str(entry['link']))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# Actually handling the arguments that come into the container.
for current_argument, current_value in arguments:
    if current_argument in ("-h", "--help"):
        print ("To Do.  See README.")
        break
    #elif current_argument in ("-s", "--t.sc"):
        #print ("Pass to T.sc and attempt to create queries")
    if current_argument in ("--report"):
        global report_request
        report_request = True
    if current_argument in ("-f", "--feed"):
        #print (("Enabling special output mode (%s)") % (current_value))
        if current_value == "us-cert":
            query_populate('https://www.us-cert.gov/ncas/alerts.xml', current_value.upper())
        elif current_value == "ms-isac" or current_value == "cis":
            query_populate('https://www.cisecurity.org/feed/advisories', current_value.upper())
        elif current_value == "cert":
            query_populate('https://www.kb.cert.org/vuls/atomfeed', current_value.upper())
        elif current_value == "ics-cert":
            query_populate('https://www.us-cert.gov/ics/advisories/advisories.xml', current_value.upper())
        elif current_value == "acsc":
            query_populate('https://www.cyber.gov.au/rssfeed/2', current_value.upper())
        else:
            print("Input a valid feed")
            exit
