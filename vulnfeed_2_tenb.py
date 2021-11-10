#!/usr/bin/env python
import feedparser
import re
from tenable.sc import TenableSC, ConnectionError
import os
from decouple import config, UndefinedValueError
import getopt, sys
import requests
import csv
from jinja2 import Environment, FileSystemLoader, BaseLoader
from phpserialize import serialize, unserialize
import base64
import ast
from bs4 import BeautifulSoup
import html
import json
import logging

#logging.basicConfig(level=logging.CRITICAL)

# Set some variables that need setting (pulled from .env file passed to container or seen locally in the same folder as script)
try:
    sc_address = config('SC_ADDRESS')
    sc_access_key = config('SC_ACCESS_KEY')
    sc_secret_key = config('SC_SECRET_KEY')
    sc_port = config('SC_PORT', default=443)
    debug_set = config('DEBUG', cast=bool, default=False)
except UndefinedValueError as err:
    print("Please review the documentation and define the required connection details in an environment file.")
    print()
    raise SystemExit(err)

if debug_set is True:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.CRITICAL)

report_request = False
alert_request = False
asset_request = False
arc_request = False
dashboard_request = False
feed_URL = ""
email_list = ""

# Handle arguments passed to script.  Note Help is defined but not yet supported.
full_cmd_arguments = sys.argv
argument_list = full_cmd_arguments[1:]
short_options = "hfre:"
long_options = ["help", "feed=", "report", "alert", "email=", "asset", "arc", "dashboard"]

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
    try:
        sc = TenableSC(sc_address, port=sc_port)
        sc.login(access_key=sc_access_key, secret_key=sc_secret_key)
    except (NameError) as err:
        print("Please verify connection details.")
        exit()
    except (ConnectionError) as err:
        raise SystemExit(err)
    return sc

## Pull all existing queries from T.sc that this API user can see.
#def get_tsc_queries(sc):
#    sc_queries = sc.queries.list()

# Pull all existing assets from T.sc that this API user can see.
#def get_tsc_assets(sc):
#    sc_assets = sc.asset_lists.list()

# Function to de-dupe CVE list.  Basically convert to a dictionary and back to a list.
def de_dup_cve(x):
    return list(dict.fromkeys(x))

# Main function to pull feeds and query tenable
def query_populate():#input_url, feed_source, sc, email_list):
    if feed == "CISA":
        try:
            with requests.Session() as s:
                download = s.get("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv")
        except:
            print("Something went wrong with the CISA feed.")
            exit()
        decoded_download = download.content.decode('utf-8')
        cisa_data = csv.reader(decoded_download.splitlines(), delimiter=',')
        next(cisa_data, None) #skip the headers
        due_date = set()
        for row in cisa_data:
            due_date.add(row[7])
        for row in cisa_data:
            if row[7] in 
        print(cisa_data)
        exit()
        cisa_cve = cisa_parse(cisa_data)
        exit()
    try:
        feed_details = feedparser.parse(feed_URL)
        if feed_details.feed.title:
            pass
    except (KeyError, AttributeError):
        print("Something looks to be wrong with the", feed, "feed. Please verify connectivity.")
        exit()
    for entry in feed_details.entries:
        advisory_cve = []
        entry_title = ""
        # Search through the text of the advisory and pull out any CVEs
        if feed == "CERT":
            advisory_cve = cert_search(entry)
            entry_title = entry.title
        elif feed == "ICS-CERT":
            advisory_cve = ics_cert_search(entry)
            entry_title = entry.title
        elif feed == "TENABLE":
            advisory_cve = tenable_search(entry)
            entry_title = entry.title
        elif feed == "CIS" or feed == "MS-ISAC":
            try:
                if feed == "CIS" or feed == "MS-ISAC":
                    cis_id = re.search(r"advisory number:.{1,150}(\d{4}-\d{2,5})", str(entry.summary_detail), flags=re.IGNORECASE | re.DOTALL).group(1)
                    entry_title = entry.title + " (" + cis_id + ")"
                    advisory_cve = re.findall("(CVE-\d{4}-\d{1,5})", str(entry.summary_detail))
            except AttributeError:
                entry_title = entry.title
                advisory_cve = re.findall("(CVE-\d{4}-\d{1,5})", str(entry.summary_detail))
                print("Something went wrong parsing the feed looking for the advisory ID")
        else:    
            entry_title = entry.title
            advisory_cve = re.findall("(CVE-\d{4}-\d{1,5})", str(entry.summary_detail))
        # de-dupe any CVEs that are listed multiple times
        cves = de_dup_cve(advisory_cve)
        # If there aren't any, start over on the next article
        if not cves:
            print("No CVEs listed in article:", entry_title, "skipping.")
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
            print("No detection plugins found for CVEs in", entry_title, "skipping.")
            continue
        #sc_queries = sc.queries.list()
        for x in range(len(sc_queries['usable'])):
            if entry_title == sc_queries['usable'][x]['name']:
                print("There is an existing query for", entry_title, "skipping.")
                query_id = sc_queries['usable'][x]['id']
                break
        else:
            # Turn the CVEs into a comma list
            cve_s = ', '.join(cves)
            # Create the Query
            query_response = sc.queries.create(entry_title, 'sumid', 'vuln', ('cveID', '=', cve_s), tags=str(feed))
            query_id = query_response['id']
            print("Created a query for", entry_title)
        if asset_request is True:
            skip_asset = False 
            for x in range(len(sc_assets['usable'])):
                if entry_title == sc_assets['usable'][x]['name']:
                    print("There is an existing asset for", entry_title, "skipping.")
                    skip_asset = True
                    break
            if skip_asset is False:
                gen_asset(entry, cves, entry_title)
                print("Created an asset for", entry_title)
        if report_request is True:
            entry_description = entry_parse(entry.summary)
            cve_s = ', '.join(cves)
            skip_report = False
            
            # Make the Report Name usable (replace variables)
            report_name = str(template_report_name).replace("{{ Feed }}", feed).replace("{{ Entry_Title }}", entry_title) 

            for x in range(len(sc_reports['response']['usable'])):
                if report_name == sc_reports['response']['usable'][x]['name']:
                    print("There is an existing report for", report_name, "skipping.")
                    report_id = sc_reports['response']['usable'][x]['id']
                    skip_report = True
                    break
            if skip_report is False:
                report_id = gen_report(entry, entry_description, cve_s, entry_title)
                print("Created an report for", report_name)
        if dashboard_request is True:
            entry_description = entry_parse(entry.summary)
            cve_s = ', '.join(cves)
            skip_dashboard = False
            
            # Make the Dashboard Name usable (replace variables)
            dashboard_name = dashboard_template_name[0].replace("{{ Feed }}", feed).replace("{{ Entry_Title }}", entry_title)

            for x in range(len(sc_dashboards['response']['usable'])):
                if dashboard_name == sc_dashboards['response']['usable'][x]['name']:
                    print("There is an existing dashboard for", dashboard_name, "skipping.")
                    dashboard_id = sc_dashboards['response']['usable'][x]['id']
                    skip_dashboard = True
                    break
            if skip_dashboard is False:
                dashboard_id = gen_dashboard(entry, entry_description, cve_s, entry_title)
                print("Created an dashboard for", dashboard_name)

        if alert_request is True: # and report_request is False:
            alert_name = feed + ": " + entry_title
            skip_alert = False
            for x in range(len(sc_alerts['usable'])):
                if alert_name == sc_alerts['usable'][x]['name']:
                    print("There is an existing alert for", alert_name, "skipping.")
                    skip_alert = True
                    break
            if skip_alert is False:
                gen_alert(report_id, query_id, entry, alert_name, entry_title)
    
        if arc_request is True:
            cve_s = ', '.join(cves)
            skip_arc = False
            skip_arc_entry = False
            for x in range(len(sc_arcs['response']['usable'])):
                if arc_name == sc_arcs['response']['usable'][x]['name']:
                    skip_arc = True
                    for y in range(len(sc_arcs['response']['usable'][x]['policyStatements'])):
                        if entry_title == sc_arcs['response']['usable'][x]['policyStatements'][y]['label']:
                            print("There is an existing ARC entry for", entry_title, "skipping")
                            skip_arc_entry = True
                            break
                        else:
                            arc_id = sc_arcs['response']['usable'][x]['id']
            if skip_arc is False:
                gen_arc(entry, cve_s, entry_title)
                print("Created an ARC for", arc_name)
            if skip_arc_entry is False and skip_arc is True:
                gen_arc_policy(entry, cve_s, arc_id, entry_title)
                print("Created an ARC Policy Statement for", entry_title, "in", arc_name)

# Generate an arc for the first time
def gen_arc(entry, cve_s, entry_title):
    Entry_Title = entry_title
    cve_list = cve_s

    # Load the definition template as a jinja template
    env = Environment(loader = FileSystemLoader('./templates'), trim_blocks=True, lstrip_blocks=True)
    arc_template_def = env.get_template('arc_definition.txt')

    #Render the definition template with data and print the output
    arc_raw = arc_template_def.render(cve_list=cve_list)

    # Convert the now rendered template back into a format that tsc can understand (base64 encoded PHP serilaized string)
    arc_raw = ast.literal_eval(arc_raw)
    arc_def_output = base64.b64encode(serialize(arc_raw))

    # Render the full XML report template and write the output to a file that we'll then upload to tsc.
    arc = env.get_template('arc_working_template.txt')
    arc_xml = arc.render(Entry_Title=Entry_Title, Feed=feed, arc_output=arc_def_output.decode('utf8'))
    
    arc_name = Entry_Title.replace(" ","").replace(":","-")[:15] + "_arc.xml"
    generated_tsc_arc_file = open(arc_name, "w")
    generated_tsc_arc_file.write(arc_xml)
    generated_tsc_arc_file.close()

    # Upload the report to T.sc
    generated_tsc_arc_file = open(arc_name, "r")
    tsc_arc_file = sc.files.upload(generated_tsc_arc_file)
    arc_data = { "name":"","filename":str(tsc_arc_file), "order":"0" }
    arc_post = sc.post('arc/import', json=arc_data).text
    arc_post = json.loads(arc_post)
    global arc_id
    arc_id = arc_post['response']['id']
    generated_tsc_arc_file.close()

    #Grab a new copy of the ARCs in T.sc, cause we just created a new one
    global sc_arcs
    sc_arcs = sc.get('arc').text
    sc_arcs = json.loads(sc_arcs)


# Create a new arc policy statement
def gen_arc_policy(entry, cve_s, arc_id, entry_title):
    Entry_Title = entry_title
    cve_list = cve_s
    arc_id = "arc/" + arc_id

    sc_arc_feed = sc.get(arc_id).text
    sc_arcs_feed = json.loads(sc_arc_feed)

    sc_arc_policies = sc_arcs_feed['response']['policyStatements']

    env = Environment(loader = FileSystemLoader('./templates'), trim_blocks=True, lstrip_blocks=True)
    arc_template_def = env.get_template('arc_policy.txt')

    #Render the definition template with data and print the output
    arc_raw = arc_template_def.render(cve_list=cve_list, Entry_Title=Entry_Title)
    arc_raw = json.loads(arc_raw)
    sc_arc_policies.append(arc_raw)
    sc_arc_policies_post = { 'policyStatements': sc_arc_policies, 'focusFilters': [], "schedule":{"start":"TZID=UTC:20200707T193300","repeatRule":"FREQ=DAILY;INTERVAL=1","type":"ical","enabled":"true"} }
    arc_patch = sc.patch(arc_id, json=sc_arc_policies_post).text
    arc_patch = json.loads(arc_patch)


# Generate a canned t.sc report about the entry
def gen_report(entry, entry_description, cve_s, entry_title):
    Entry_Title = entry_title.replace("'","")
    Entry_ShortDesc = "For more information, please see the full page at " + entry.link
    Entry_Summary = entry_description.replace("'","").replace("\\","/")
    cve_list = cve_s

    # Load the definition template as a jinja template
    env = Environment(loader = FileSystemLoader('./templates'), trim_blocks=True, lstrip_blocks=True)
    template_def = env.get_template('definition.txt')

    #Render the definition template with data and print the output
    report_raw = template_def.render(Entry_Title=Entry_Title, Entry_ShortDesc=Entry_ShortDesc, Entry_Summary=Entry_Summary, cve_list=cve_list)

    # Convert the now rendered template back into a format that tsc can understand (base64 encoded PHP serilaized string)
    report_raw = ast.literal_eval(report_raw)
    report_output = base64.b64encode(serialize(report_raw))

    # Render the full XML report template and write the output to a file that we'll then upload to tsc.
    report = env.get_template('sc_working_template.txt')
    report_xml = report.render(Entry_Title=Entry_Title, Feed=feed, Entry_ShortDesc=Entry_ShortDesc, report_output=report_output.decode('utf8'))
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

# Generate a canned t.sc dashboard about the entry
def gen_dashboard(entry, entry_description, cve_s, entry_title):
    Entry_Title = entry_title.replace("'","")
    Entry_ShortDesc = "For more information, please see the full page at " + entry.link
    Entry_Summary = entry_description.replace("'","").replace("\\","/")
    cve_list = cve_s

    dashboard_template_file = open('./templates/sc_working_dashboard_template.txt', "r")
    dashboard_template_contents = dashboard_template_file.read()
    
    
    for x in range(len(re.findall("<definition>(.+)</definition>", str(dashboard_template_contents)))): 
        r_dashboard_component = Environment(loader=BaseLoader()).from_string(dashboard_components_list[x])
        component_render = r_dashboard_component.render(Entry_Title=Entry_Title, Entry_ShortDesc=Entry_ShortDesc, Entry_Summary=Entry_Summary, cve_list=cve_list)
        component_raw = ast.literal_eval(component_render)
        component_output = base64.b64encode(serialize(component_raw))

        dashboard_template_contents = str(dashboard_template_contents).replace('{{ dashboard_output }}', component_output.decode("utf8"), 1)
        #print(dashboard_template_contents)  
        #dashboard_template_contents.replace('re.findall("<definition>(.+)</definition>", str(dashboard_template_contents)[x])',dashboard_components_list[x])
 
    #print(dashboard_template_contents)       
    
    r_dashboard_full = Environment(loader=BaseLoader()).from_string(dashboard_template_contents)
    dashboard_full = r_dashboard_full.render(Entry_Title=Entry_Title, Entry_ShortDesc=Entry_ShortDesc, Entry_Summary=Entry_Summary, cve_list=cve_list, Feed=feed)
    

    # Write the output to a file that we'll then upload to tsc.
    dashboard_name = Entry_Title.replace(" ","").replace(":","-")[:15] + "_dashboard.xml"
    generated_tsc_dashboard_file = open(dashboard_name, "w")
    generated_tsc_dashboard_file.write(dashboard_full)
    generated_tsc_dashboard_file.close()

    # Upload the dashboard to T.sc
    generated_tsc_dashboard_file = open(dashboard_name, "r")
    tsc_file = sc.files.upload(generated_tsc_dashboard_file)
    dashboard_data = { "name":"","order":"1","filename":str(tsc_file) }
    dashboard_post = sc.post('dashboard/import', json=dashboard_data).text
    dashboard_post = json.loads(dashboard_post)
    dashboard_id = dashboard_post['response']['id']
    generated_tsc_dashboard_file.close()

    return dashboard_id

# Generate an alert (requires a query and report to be created)
def gen_alert(report_id, query_id, entry, alert_name, entry_title):
    alert_description = "For more information, please see the full page at " + entry.link
    alert_schedule = {"start":"TZID=America/New_York:20200622T070000","repeatRule":"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO","type":"ical","enabled":"true"}
    if report_request is True: 
        sc.alerts.create(query={"id":query_id}, schedule=alert_schedule, data_type="vuln", name=alert_name, description=alert_description, trigger=('sumip','>=','1'), always_exec_on_trigger=True, action=[{'type': 'report','report':{'id': report_id}}])
        print("Created an reporting alert for", entry_title)
    elif report_request is False and len(email_list) >= 5:
        sc.alerts.create(query={"id":query_id}, schedule=alert_schedule, data_type="vuln", name=alert_name, description=alert_description, trigger=('sumip','>=','1'), always_exec_on_trigger=True, action=[{'type': 'email','subject': alert_name, 'message': alert_description, 'addresses': email_list, 'includeResults': 'true'}])
        print("Created an email alert for", entry_title)
    else:
        print("Alert creation specified, but no report or email recipients noted, exiting.")
        exit()

# Generate an asset
def gen_asset(entry, cves, entry_title):
    asset_rules = ['any']
    for cve in cves:
        cve_string = "CVE|" + cve
        asset_rules.append(('xref','eq',cve_string))
    asset_rules = tuple(asset_rules)
    asset_name = entry_title
    asset_description = "For more information, please see the full page at " + entry.link
    output = sc.asset_lists.create(name=asset_name,description=asset_description,list_type="dynamic",tags=feed,rules=asset_rules)

# Get a reasonable summary if one isn't provided
def entry_parse(entry_description):
    entry_description = html.unescape(entry_description)
    entry_description = entry_description.replace("<p>", " ").replace("<br/>"," ").replace("\n","")
    entry_description = BeautifulSoup(entry_description, 'lxml') #features="html.parser")
    return entry_description.get_text()[:500] + (entry_description.get_text()[500:] and '...')

# CMU CERT doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def cert_search(entry):
    url = re.search("(https://kb\.cert\.org/vuls/id/\d{3,})", str(entry))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# ICS CERT doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def ics_cert_search(entry):
    url = re.search("(https://us-cert\.cisa\.gov/ics/advisories/[icsam]{4,5}-[\d\-]{5,20})", str(entry))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# Tenable sometimes doesn't publish enough info in their feed, we need to grab and parse the actual articles.
def tenable_search(entry):
    url = re.search("(https://www\.tenable\.com/blog/.+)", str(entry['link']))
    r = requests.get(url.group(0))
    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

# ACSC doesn't publish enough info in their feed, we need to grab and parse the actual articles.
# Commenting out; disabling the ACSC feed because they removed their RSS feed :( 7-8-20, v1.1.1
#def acsc_search(entry):
#    url = re.search("(https://www\.cyber\.gov\.au/threats/.+)", str(entry['link']))
#    r = requests.get(url.group(0))
#    return re.findall("(CVE-\d{4}-\d{1,5})", str(r.text))

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
    if current_argument in ("-e","--email"):
        passed_emails = ""
        passed_emails = current_value.split(",")
        email_list = email_validate(passed_emails)
    if current_argument in ("-r", "--report"):
        report_request = True
    if current_argument in ("--alert"):
        alert_request = True
    if current_argument in ("--arc"):
        arc_request = True
    if current_argument in ("--asset"):
        asset_request = True
    if current_argument in ("--dashboard"):
        dashboard_request = True
    if current_argument in ("-f", "--feed"):
        feed = current_value.upper()
        if current_value == "us-cert":
            feed_URL = "https://www.us-cert.gov/ncas/alerts.xml"
        elif current_value == "ms-isac" or current_value == "cis":
            feed_URL = "https://www.cisecurity.org/feed/advisories"
        elif current_value == "cert":
            feed_URL = "https://www.kb.cert.org/vuls/atomfeed"
        elif current_value == "ics-cert":
            feed_URL = "https://us-cert.cisa.gov/ics/advisories/advisories.xml"
        # ACSC stopped their feed :(
        #elif current_value == "acsc":
        #    feed_URL = "https://www.cyber.gov.au/rssfeed/2"
        elif current_value == "tenable":
            feed_URL = "https://www.tenable.com/blog/cyber-exposure-alerts/feed"
        elif current_value == "cisa":
            feed_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

        else:
            print("Input a valid feed")
            exit()

# Based on the data provided, decide what to do
if len(feed_URL) >= 10:
    sc = tsc_login()
    sc_queries = sc.queries.list()
    if asset_request is True:
        sc_assets = sc.asset_lists.list()
    if report_request is True:
        sc_reports = sc.get('reportDefinition').text
        sc_reports = json.loads(sc_reports)
        # Check to see if a custom template is provided
        if os.path.isfile('./templates/custom_sc_report.xml'):
            sc_template_path = './templates/custom_sc_report.xml'
        else:
            sc_template_path = "./templates/sc_template.xml"

        # Let's read the base sc template and pull out the report definition and other info
        sc_template_file = open(sc_template_path, "r")
        template_contents = sc_template_file.read()
        template_def = re.search("<definition>(.+)</definition>", str(template_contents))
        template_report_name = re.search("<name>(.+)</name>", str(template_contents)).group(1)
        #template_report_desc = re.search("<description>(.+)</description>", str(template_contents))
        sc_template_file.close()

        # replace def with tag to be substituted later
        new_sc_template = re.sub("<definition>(.+)</definition>", "<definition>{{ report_output }}</definition>", str(template_contents))
        sc_working_template_file = open('./templates/sc_working_template.txt', "w")
        sc_working_template_file.write(new_sc_template)
        sc_working_template_file.close()

        # Let's put the encoded report def into a format we can work with
        template_def = base64.b64decode(template_def.group(1))
        template_def = unserialize(template_def, decode_strings=True)

        # Replace the CVE placeholder with something we can swap out later
        template_def = str(template_def).replace("CVE-1990-0000", "{{ cve_list }}")

        # Write this definition template to a file
        template_def_file = open("./templates/definition.txt", "w")
        template_def_file.write(template_def)
        template_def_file.close()
    if arc_request is True:
        sc_arcs = sc.get('arc').text
        sc_arcs = json.loads(sc_arcs)
        arc_name = feed + " Advisory Alerts"
        if os.path.isfile('./templates/custom_arc_report.xml'):
            arc_template_path = './templates/custom_arc_report.xml'
        else:
            arc_template_path = "./templates/arc_template.xml"

        # Let's read the base sc template and pull out the report definition and other info
        arc_template_file = open(arc_template_path, "r")
        arc_template_contents = arc_template_file.read()
        arc_template_def = re.search("<definition>(.+)</definition>", str(arc_template_contents))
        arc_template_name = re.search("<name>(.+)</name>", str(arc_template_contents)).group(1)
        arc_template_file.close()

        # replace def with tag to be substituted later
        new_arc_template = re.sub("<definition>(.+)</definition>", "<definition>{{ arc_output }}</definition>", str(arc_template_contents))
        arc_policy_def = re.search("(<policyStatement>.+</policyStatement>)", str(new_arc_template))
        arc_working_template_file = open('./templates/arc_working_template.txt', "w")
        arc_working_template_file.write(new_arc_template)
        arc_working_template_file.close()

        # Let's put the encoded report def into a format we can work with
        arc_template_def = base64.b64decode(arc_template_def.group(1))
        arc_template_def = unserialize(arc_template_def, decode_strings=True)

        # Replace the CVE placeholder with something we can swap out later
        arc_template_def = str(arc_template_def).replace("CVE-1990-0000", "{{ cve_list }}")

        # Write this definition template to a file
        arc_template_def_file = open("./templates/arc_definition.txt", "w")
        arc_template_def_file.write(arc_template_def)
        arc_template_def_file.close()

    if alert_request is True:
        sc_alerts = sc.alerts.list()

    if dashboard_request is True:
        sc_dashboards = sc.get('dashboard').text
        sc_dashboards = json.loads(sc_dashboards)
        # Check to see if a custom template is provided
        if os.path.isfile('./templates/custom_sc_dashboard.xml'):
            sc_dashboard_template_path = './templates/custom_sc_dashboard.xml'
        else:
            sc_dashboard_template_path = "./templates/sc_dashboard_template.xml"

        # Let's read the base sc template and pull out the dashboard definitions and other info
        sc_dashboard_template_file = open(sc_dashboard_template_path, "r")
        dashboard_template_contents = sc_dashboard_template_file.read()
        dashboard_template_def = re.findall("<definition>(.+)</definition>", str(dashboard_template_contents))
        dashboard_template_name = re.findall("<name>(.+)</name>", str(dashboard_template_contents))
        dashboard_template_desc = re.findall("<description>(.+)</description>", str(dashboard_template_contents))
        sc_dashboard_template_file.close()

        # replace def with tag to be substituted later
        new_sc_dashboard_template = re.sub("<definition>(.+)</definition>", "<definition>{{ dashboard_output }}</definition>", str(dashboard_template_contents))
        sc_working_dashboard_template_file = open('./templates/sc_working_dashboard_template.txt', "w")
        sc_working_dashboard_template_file.write(new_sc_dashboard_template)
        sc_working_dashboard_template_file.close()
        
        dashboard_components_list = []
        # Let's put the encoded dashboard def into a format we can work with
        for component_def in dashboard_template_def:
            component_template_def = base64.b64decode(component_def)
            component_template_def = unserialize(component_template_def, decode_strings=True)
            #print(component_template_def)
            # Replace the CVE placeholder with something we can swap out later
            component_template_def = str(component_template_def).replace("CVE-1990-0000", "{{ cve_list }}")
            dashboard_components_list.append(component_template_def)

        # Write this definition template to a file
        #dashboard_template_def_file = open("./templates/dashboard_definition.txt", "w")
        #dashboard_template_def_file.write(str(dashboard_components_list))
        #dashboard_template_def_file.close()

    query_populate()
else:
    print("Please specify a feed or --help")
