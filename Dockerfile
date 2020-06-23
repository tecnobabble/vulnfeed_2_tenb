FROM python:3.8-slim-buster
  
RUN pip install pytenable feedparser python-decouple requests BeautifulSoup4 phpserialize jinja2 lxml

COPY vulnfeed_2_tenb.py /
COPY templates /templates
RUN chmod +x /vulnfeed_2_tenb.py; 
ENTRYPOINT ["/vulnfeed_2_tenb.py"]
