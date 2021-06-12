FROM amazonlinux:2
RUN curl -fsSL https://rpm.nodesource.com/setup_12.x | bash
RUN yum install -y nodejs gcc-c++ make
RUN yum install -y git
RUN npm i
RUN ls
RUN npm test
