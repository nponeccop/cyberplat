FROM amazonlinux:2
RUN curl -fsSL https://rpm.nodesource.com/setup_12.x | bash
RUN yum install -y nodejs gcc-c++ make git
COPY package.json /home/build/package.json
WORKDIR /home/build
RUN npm i
COPY . /home/build
RUN npm ci
