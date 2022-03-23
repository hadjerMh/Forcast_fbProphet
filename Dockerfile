FROM python:3.8.10
#FROM ubuntu:20.04

ENV FLASK_APP run.py 

# We copy just the requirements.txt first to leverage Docker cache
COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN python -m pip install --upgrade pip

#RUN apk add --no-cache musl-dev gcc libffi-dev g++

#RUN apk update && apk add gfortran build-base openblas-dev libffi-dev

#RUN apk update && apk add python3-dev gcc libc-dev

#RUN python3 -m pip install matplotlib

RUN pip install -r requirements.txt

COPY . /app

CMD ["python", "-m" , "flask", "run", "--host=0.0.0.0"]
