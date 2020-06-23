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
import html
import json

# Set some variables that need setting (pulled from .env file passed to container or seen locally in the same folder as script)
sc_address = config('SC_ADDRESS')
sc_access_key = config('SC_ACCESS_KEY')
sc_secret_key = config('SC_SECRET_KEY')
sc_port = config('SC_PORT', default=443)

report_request = False
alert_request = False

# Handle arguments passed to script.  Note Help is defined but not yet supported.
full_cmd_arguments = sys.argv
argument_list = full_cmd_arguments[1:]
short_options = "hfrae:"
long_options = ["help", "feed=", "report", "alert", "email="]

try:
    arguments, values = getopt.getopt(argument_list, short_options, long_options)
except getopt.error as err:
    # Output error, and return with an error code
    print (str(err))
    sys.exit(2)

#####################
# Most of the code that does the actual work
#####################

# Login to Tenable.sc
def tsc_login():
    sc = TenableSC(sc_address, port=sc_port)
    sc.login(access_key=sc_access_key, secret_key=sc_secret_key)
    return sc

# Pull all existing queries from T.sc that this API user can see.
def get_tsc_queries(sc):
    sc_queries = sc.queries.list()

# Function to de-dupe CVE list.  Basically convert to a dictionary and back to a list.
def de_dup_cve(x):
    return list(dict.fromkeys(x))

# Main function to pull feeds and query tenable
def query_populate():#input_url, feed_source, sc, email_list):
    feed_details = feedparser.parse(feed_URL)
    for entry in feed_details.entries:
        # Search through the text of the advisory and pull out any CVEs
        if feed == "CERT":
            advisory_cve = cert_search(entry)
        elif feed == "ICS-CERT":
            advisory_cve = ics_cert_search(entry)
        elif feed == "ACSC":
            advisory_cve = acsc_search(entry)
        else:
            advisory_cve = re.findall("(CVE-\d{4}-\d{1,5})", str(entry.summary_detail))
        # de-dupe any CVEs that are listed multiple times
        cves = de_dup_cve(advisory_cve)
        # If there aren't any, start over on the next article
        if not cves:
            print("No CVEs listed in article:", entry.title, "skipping.")
            continue
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
        sc_queries = sc.queries.list()
        for x in range(len(sc_queries['usable'])):
            if entry.title == sc_queries['usable'][x]['name']:
                print("There is an existing query for", entry.title, "skipping.")
                break
        else:
            # Turn the CVEs into a comma list
            cve_s = ', '.join(cves)
            # Create the Query
            query_response = sc.queries.create(entry.title, 'sumid', 'vuln', ('cveID', '=', cve_s), tags=str(feed))
            query_id = query_response['id']
            print("Created a query for", entry.title)
            if report_request is True:
                entry_description = entry_parse(entry.summary)
                cve_s = ', '.join(cves)
                report_id = gen_report(entry, entry_description, cve_s)
                print("Created a report for", entry.title)
            if alert_request is True and report_request is False:
                gen_alert(0, query_id, entry)
                #print("Created an email alert for", entry.title)
            elif alert_request is True:
                gen_alert(report_id, query_id, entry)
                print("Created an alert for", entry.title)

# Generate a canned t.sc report about the entry
def gen_report(entry, entry_description, cve_s):
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
    report_xml = report.render(Entry_Title=Entry_Title, Feed=feed, Entry_URL=Entry_URL, report_output=report_output.decode('utf8'))
    report_name = Entry_Title.replace(" ","").replace(":","-")[:15] + "_report.xml"
    generated_tsc_report_file = open(report_name, "w")
    generated_tsc_report_file.write(report_xml)
    generated_tsc_report_file.close()

    # Upload the report to T.sc
    generated_tsc_report_file = open(report_name, "r")
    tsc_file = sc.files.upload(generated_tsc_report_file)
    report_data = { "name":"","filename":str(tsc_file) }
    report_post = sc.post('reportDefinition/import', json=report_data).text
    report_post = json.loads(report_post)
    report_id = report_post['response']['id']
    generated_tsc_report_file.close()

    # Configure email on the report if set
    if len(email_list) >= 5:
        report_patch_path = "reportDefinition/" + str(report_id)
        report_email_info = { "emailTargets": email_list }
        sc.patch(report_patch_path, json=report_email_info)
    return report_id


# Generate an alert (requires a query and report to be created)
def gen_alert(report_id, query_id, entry):
    alert_name = feed + ": " + entry.title
    alert_description = "For more information, please see the full page at " + entry.link
    alert_schedule = {"start":"TZID=America/New_York:20200622T070000","repeatRule":"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO","type":"ical","enabled":"true"}
    if report_request is True: 
        sc.alerts.create(query={"id":query_id}, schedule=alert_schedule, data_type="vuln", name=alert_name, description=alert_description, trigger=('sumip','>=','1'), always_exec_on_trigger=True, action=[{'type': 'report','report':{'id': report_id}}])
    elif report_request is False and len(email_list) >= 5:
        #email_s = ','.join(email_list)
        sc.alerts.create(query={"id":query_id}, schedule=alert_schedule, data_type="vuln", name=alert_name, description=alert_description, trigger=('sumip','>=','1'), always_exec_on_trigger=True, action=[{'type': 'email','subject': alert_name, 'message': alert_description, 'addresses': email_list, 'includeResults': 'true'}])
        print("Created an email alert for", entry.title)
    else:
        print("Alert creation specified, but no report or email recipients noted, exiting.")
        exit

# Get a reasonable summary if one isn't provided
def entry_parse(entry_description):
    entry_description = html.unescape(entry_description)
    entry_description = entry_description.replace("<p>", " ").replace("<br/>"," ").replace("\n","")
    entry_description = BeautifulSoup(entry_description, 'lxml') #features="html.parser")
    return entry_description.get_text()[:500] + (entry_description.get_text()[500:] and '...')

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

# Define a function for validating an email
def email_validate(email):
    regex = '[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}'
    email_list = []
    for i in email:
        if(re.search(regex,i)):
            email_list += [i]
        else:
            print("Invalid Email Address:", i)
            exit()
    email_list = ','.join(email_list)
    return email_list

# Actually handling the arguments that come into the container.
for current_argument, current_value in arguments:
    if current_argument in ("-h", "--help"):
        print ("To Do.  See README.") # TO DO: Turn into function
        exit()
    #elif current_argument in ("-s", "--t.sc"): # Not implemented until we have T.io functionality
        #print ("Pass to T.sc and attempt to create queries")
    if current_argument in ("--email"):
        passed_emails = ""
        passed_emails = current_value.split(",")
        email_list = email_validate(passed_emails)
    if current_argument in ("--report"):
        report_request = True
    if current_argument in ("--alert"):
        alert_request = True
    if current_argument in ("-f", "--feed"):
        #print (("Enabling special output mode (%s)") % (current_value))
        feed = current_value.upper()
        if current_value == "us-cert":
            feed_URL = "https://www.us-cert.gov/ncas/alerts.xml"
            #query_populate('https://www.us-cert.gov/ncas/alerts.xml', current_value.upper())
        elif current_value == "ms-isac" or current_value == "cis":
            feed_URL = "https://www.cisecurity.org/feed/advisories"
        elif current_value == "cert":
            feed_URL = "https://www.kb.cert.org/vuls/atomfeed"
        elif current_value == "ics-cert":
            feed_URL = "https://www.us-cert.gov/ics/advisories/advisories.xml"
        elif current_value == "acsc":
            feed_URL = "https://www.cyber.gov.au/rssfeed/2"
        else:
            print("Input a valid feed")
            exit()

# Based on the data provided, decide what to do
if feed_URL:
    sc = tsc_login()
    query_populate()
