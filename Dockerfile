FROM python:3.8

ENV HOME /root
WORKDIR /root

RUN mkdir -p /root/log

COPY ./requirements.txt ./requirements.txt
COPY ./server.py ./server.py
COPY ./templates ./templates
COPY ./util ./util

RUN pip3 install -r requirements.txt

EXPOSE 8080

CMD ["python", "server.py"]