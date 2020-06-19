#!/usr/bin/env python

from jinja2 import Environment, FileSystemLoader
import re
from phpserialize import serialize, unserialize
import base64
import ast

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

#cve_list = ','.join(cve_list)

Entry_Title = "test title"
cve_list = "CVE-2020-0001"

#Render the definition template with data and print the output
report_raw = template_def.render(Entry_Title=Entry_Title, cve_list=cve_list)

# Convert the now rendered template back into a format that tsc can understand (base64 encoded PHP serilaized string)
report_raw = ast.literal_eval(report_raw)
report_output = base64.b64encode(serialize(report_raw))

# Render the full XML report template and write the output to a file that we'll then upload to tsc.
report = env.get_template('report.txt')
report_xml = report.render(Entry_Title=Entry_Title, report_output=report_output.decode('utf8'))
generated_tsc_report_file = open("tsc_report.xml", "w")
generated_tsc_report_file.write(report_xml)
generated_tsc_report_file.close()


