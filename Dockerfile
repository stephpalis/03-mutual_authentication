FROM python:3
RUN apt-get update && apt-get -y upgrade
RUN pip3 install --upgrade pip
RUN pip3 install protobuf
RUN pip3 install pynacl
RUN pip3 install passlib
RUN pip3 install argon2_cffi
COPY . /app
WORKDIR /app
ENTRYPOINT ["python", "/app/authentication.py"]
