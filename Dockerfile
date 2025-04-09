FROM isaudits/kali:msf

WORKDIR /root/

ENV LC_ALL C.UTF-8
ENV STAGING_KEY=RANDOM
ENV DEBIAN_FRONTEND noninteractive

RUN touch ~/.hushlogin && \
    apt-get update && apt-get upgrade -y && apt-get install -y \
        nmap tmux python3-libtmux impacket-scripts python3-impacket responder && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

COPY mitm.py check-smb-signing.sh /opt/
COPY tmux.conf /root/.tmux.conf
ENTRYPOINT ["python3", "/opt/mitm.py"]

