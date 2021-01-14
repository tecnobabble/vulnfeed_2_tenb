FROM python:3.9-slim-buster

RUN /usr/local/bin/python -m pip install --upgrade pip  
RUN pip3 install pytenable feedparser python-decouple requests BeautifulSoup4 phpserialize jinja2 lxml
RUN apt-get update; apt-get -y upgrade
RUN export PYTHONUNBUFFERED=1
COPY vulnfeed_2_tenb.py /
COPY templates /templates
RUN chmod +x /vulnfeed_2_tenb.py; 
ENTRYPOINT ["/vulnfeed_2_tenb.py"]
