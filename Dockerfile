#FROM debian:stable
FROM isaudits/msf:minimal

WORKDIR /root/

ENV LC_ALL C.UTF-8
ENV STAGING_KEY=RANDOM
ENV DEBIAN_FRONTEND noninteractive

ENV EMPIRE_USER='empireadmin'
ENV EMPIRE_PASS='Password123!'

ENV DEPS_GENERAL='git curl wget sudo locales lsb-release apt-transport-https net-tools nmap tmux python3-dev python3-pip python3-requests'
ENV DEPS_REMOVE='build-essential make g++'

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
        $DEPS_GENERAL && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    #pip install -U cryptography && \
    pip3 install impacket && \
    pip3 install libtmux

RUN git clone --depth=1 https://github.com/byt3bl33d3r/DeathStar /opt/DeathStar && \
    cd /opt/DeathStar && \
    rm -rf .git && \
    # Downgrade PIP to allow hashed requirements to install properly
    pip3 install --upgrade pip==20.2.4 && \
    pip3 install -r ./requirements.txt

RUN git clone --depth=1 https://github.com/lgandx/Responder /opt/Responder &&  \  
    rm -rf /opt/Responder/.git && \
    pip3 install netifaces && \
    sed -i "s/Challenge = Random/Challenge = 1122334455667788/g" /opt/Responder/Responder.conf

# Using BC-SECURITY fork now since original project abandoned
RUN git clone --depth=1 https://github.com/BC-SECURITY/Empire.git /opt/Empire && \
    cd /opt/Empire/ && \
    rm -rf .git && \
    cd /opt/Empire/setup/ && \
    ./install.sh && \
    # installer grabs some more stuff from repo - clean it up!
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.py check-smb-signing.sh /opt/
COPY tmux.conf /root/.tmux.conf
ENTRYPOINT ["python3", "/opt/entrypoint.py"]

