FROM alpine:latest

# Install python3 and development files
RUN apk add alpine-sdk python3 python3-dev
RUN apk add linux-headers libffi-dev openssl-dev

# Install pip
RUN python3 -m ensurepip

# Doing this makes docker & pip succeed > 20% of the time
# with really terrible internet... otherwise, it randomly
# fails...
# RUN pip3 install pycryptodome
# RUN pip3 install PyNaCl
# RUN pip3 install cryptography
# RUN pip3 install typing-extensions
# RUN pip3 install colorama
# RUN pip3 install netifaces==0.10.9
# RUN pip3 install pygments==2.6.1
# RUN pip3 install sqlalchemy
# RUN pip3 install rich
# RUN pip3 install pytablewriter
# RUN pip3 install bcrypt

# Copy pwncat source
COPY . /pwncat

# Create a working directory
RUN mkdir /work

# Setup pwncat
RUN cd /pwncat && python3 setup.py install

# Set working directory
WORKDIR /work

ENTRYPOINT ["/usr/bin/pwncat"]
