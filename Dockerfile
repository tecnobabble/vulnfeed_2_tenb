FROM python:3.10.0-slim-buster

RUN /usr/local/bin/python -m pip install --upgrade pip  
RUN pip3 install "pyTenable>=1.4.3" python-decouple requests BeautifulSoup4 phpserialize jinja2 lxml
RUN apt-get update; apt-get -y upgrade

COPY cisa_kev.py /
COPY templates /templates
RUN chmod +x /cisa_kev.py

RUN useradd -ms /bin/bash vulnfeed
RUN chown -R vulnfeed:vulnfeed /templates
USER vulnfeed
WORKDIR /home/vulnfeed

RUN export PYTHONUNBUFFERED=1
ENTRYPOINT ["/cisa_kev.py"]

HEALTHCHECK NONE
