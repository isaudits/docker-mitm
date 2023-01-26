FROM isaudits/empire

WORKDIR /root/

ENV LC_ALL C.UTF-8
ENV STAGING_KEY=RANDOM
ENV DEBIAN_FRONTEND noninteractive

ENV EMPIRE_USER='empireadmin'
ENV EMPIRE_PASS='Password123!'

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
        nmap tmux python3-libtmux python3-impacket python3-pip responder && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

RUN git clone --depth=1 https://github.com/byt3bl33d3r/DeathStar /opt/DeathStar && \
    cd /opt/DeathStar && \
    rm -rf .git && \
    # Downgrade PIP to allow hashed requirements to install properly
    pip3 install --upgrade pip==20.2.4 && \
    pip3 install -r ./requirements.txt

COPY entrypoint.py check-smb-signing.sh /opt/
COPY tmux.conf /root/.tmux.conf
ENTRYPOINT ["python3", "/opt/entrypoint.py"]

