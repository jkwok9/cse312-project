FROM python:3.8

ENV HOME /root
WORKDIR /root

RUN mkdir -p /root/log

COPY ./requirements.txt ./requirements.txt
COPY ./server.py ./server.py
COPY ./templates ./templates
COPY ./util ./util

RUN pip3 install -r requirements.txt

EXPOSE 8000

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u server.py
