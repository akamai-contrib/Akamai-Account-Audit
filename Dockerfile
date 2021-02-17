# -------------------------------------------------------------------
# Dockerfile for Python 3.7 slim and all dependencies for required to 
# run the Akamai-Account-Audit application
#
# Instructions:
# =============
# 1. Clone the repository locally
# 
# 2. Build the image
#    $ docker build --tag aka-audit:latest .
#
# 3. Start the container, allow ro access to the local .edgerc and run
#    the akamai-audit.py app. This is an example:
#    $ docker run -it --rm --name audit -v $HOME/.edgerc:/root/.edgerc:ro -v "$(pwd):/app/akamai-audit" aka-audit:latest python akamai-audit.py --type os --start 2021-01-30 --end 2021-02-10 --cpcodes xxxxxx --switchKey xxx-xxx
#
# --------------------------------------------------------------------

FROM python:3.7-slim

WORKDIR /app/akamai-audit
ADD  . /app/akamai-audit

RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "./akamai-audit.py"]