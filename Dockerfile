FROM python:3.8-slim-buster

<<<<<<< HEAD
RUN pip install pytenable feedparser python-decouple requests BeautifulSoup4 phpserialize jinja2 lxml
=======
RUN pip install pytenable feedparser python-decouple requests BeautifulSoup4 phpserialize jinja2
>>>>>>> e9922de6bea6800d25c1f72f94e3e2e3e42067af

COPY vulnfeed_2_tenb.py templates /
RUN chmod +x /vulnfeed_2_tenb.py
ENTRYPOINT ["/vulnfeed_2_tenb.py"]
