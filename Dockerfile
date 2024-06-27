FROM jenkins/jenkins:lts

USER root

# Install Python 3
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv

USER jenkins
