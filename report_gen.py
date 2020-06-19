#!/usr/bin/env python

#Import necessary functions from Jinja2 module
from jinja2 import Environment, FileSystemLoader

#Import YAML module
#import yaml

import re
from phpserialize import * #serialize, unserialize
import base64
import ast


#Load Jinja2 template

sc_template = open("templates/sc_template.xml", "rt") # open lorem.txt for reading text
template_contents = sc_template.read()         # read the entire file into a string

template_def = re.search("<definition>(.+)</definition>", str(template_contents))
template_def = base64.b64decode(template_def.group(1))
template_def = unserialize(template_def, decode_strings=True)

template_def = str(template_def).replace("CVE-1990-0000", "{{ cve_list }}")




#template_def = ast.literal_eval(template_def)

#template = serialize(template_def)

#print(template)

#print(template_def)

#myfile.close() 

env = Environment(loader = FileSystemLoader('./templates'), trim_blocks=True, lstrip_blocks=True)
template_def = env.get_template('definition.txt')


Entry_Title = "Top 10 Routinely Exploited Vulnerabilities"
cve_list = ['CVE-2017-11882', 'CVE-2017-0199', 'CVE-2017-5638', 'CVE-2012-0158', 'CVE-2019-0604', 'CVE-2017-0143', 'CVE-2018-4878', 'CVE-2017-8759', 'CVE-2015-1641', 'CVE-2018-7600', 'CVE-2019-19781', 'CVE-2019-11510']

cve_list = ','.join(cve_list)

#Render the template with data and print the output
report_raw = template_def.render(Entry_Title=Entry_Title, cve_list=cve_list)

report_raw = ast.literal_eval(report_raw)
#print(report_raw)
report_output = base64.b64encode(serialize(report_raw))

#print(report_output)
#print(report_output.decode('utf8'))

report = env.get_template('report.txt')
report_xml = report.render(Entry_Title=Entry_Title, report_output=report_output.decode('utf8'))

print(report_xml)

