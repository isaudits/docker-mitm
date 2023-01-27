FROM isaudits/empire

WORKDIR /root/

ENV LC_ALL C.UTF-8
ENV STAGING_KEY=RANDOM
ENV DEBIAN_FRONTEND noninteractive

ENV EMPIRE_USER='empireadmin'
ENV EMPIRE_PASS='Password123!'

RUN touch ~/.hushlogin && \
    apt-get update && apt-get upgrade -y && apt-get install -y \
        nmap tmux python3-libtmux impacket-scripts python3-impacket responder metasploit-framework && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

COPY entrypoint.py check-smb-signing.sh /opt/
COPY tmux.conf /root/.tmux.conf
ENTRYPOINT ["python3", "/opt/entrypoint.py"]

