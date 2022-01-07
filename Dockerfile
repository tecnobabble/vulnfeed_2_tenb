FROM python:3.10.0-slim-buster

RUN /usr/local/bin/python -m pip install --upgrade pip  
RUN pip3 install "pyTenable>=1.4.3" feedparser python-decouple requests BeautifulSoup4 phpserialize jinja2 lxml
RUN apt-get update; apt-get -y upgrade

COPY vulnfeed_2_tenb.py /
COPY templates /templates
RUN chmod +x /vulnfeed_2_tenb.py

RUN useradd -ms /bin/bash vulnfeed
RUN chown -R vulnfeed:vulnfeed /templates
USER vulnfeed
WORKDIR /home/vulnfeed

RUN export PYTHONUNBUFFERED=1
ENTRYPOINT ["/vulnfeed_2_tenb.py"]

HEALTHCHECK NONE
