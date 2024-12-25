#
# This docker file builds a container image that's based on CentOS Stream 9 and
# which includes your server as well the small Svelte demo app.
#
# Before building the container, you must log into container.cs.vt.edu
# if you don't, you'll get an error:
# Error: creating build container: initializing source docker://container.cs.vt.edu/cs3214-staff/pserv/eurolinux-centos-stream-9:latest: Requesting bearer token: invalid status code from registry 403 (Forbidden)
# Do:
#       docker login container.cs.vt.edu
#
# The build should take about 3min total.
#
# Pull from a local copy of https://hub.docker.com/r/eurolinux/centos-stream-9 
# to avoid rate limits with hub.docker.com
#
FROM container.cs.vt.edu/cs3214-staff/pserv/eurolinux-centos-stream-9

LABEL maintainer="gback@vt.edu"

# install various necessary software
RUN yum -y install gcc openssl-devel automake libtool git diffutils make procps wget
RUN dnf -y module install nodejs:20
# add a non-privileged user 'user'
RUN adduser user

# assume this user
USER user
# copy src, svelte-app directory and install-dependencies.sh into image
COPY --chown=user:user src /home/user/src
COPY --chown=user:user svelte-app /home/user/svelte-app
COPY --chown=user:user install-dependencies.sh /home/user

# install dependencies
WORKDIR /home/user
RUN sh install-dependencies.sh

# build server
WORKDIR /home/user/src
RUN make clean
RUN make

# build svelte-app
WORKDIR /home/user/svelte-app
RUN npm install
RUN npm run build
WORKDIR /home/user/svelte-app
#
# The CDN res.cloudinary.com seems to impose rate limits; fetch a local copy instead
# RUN /bin/bash get_some_mp4.sh
RUN wget -O build/vt-tour.mp4 https://courses.cs.vt.edu/cs3214/videos/demomp4s/vt-tour.mp4
RUN wget -O build/CoffeeRun.mp4 https://courses.cs.vt.edu/cs3214/videos/demomp4s/CoffeeRun.mp4
RUN wget -O build/Spring.mp4 https://courses.cs.vt.edu/cs3214/videos/demomp4s/Spring.mp4
RUN wget -O build/Agent327.mp4 https://courses.cs.vt.edu/cs3214/videos/demomp4s/Agent327.mp4
RUN wget -O build/Hero.mp4 https://courses.cs.vt.edu/cs3214/videos/demomp4s/Hero.mp4

# place a private/secret.txt file to facilitate testing
RUN test -d /home/user/svelte-app/build/private || mkdir /home/user/svelte-app/build/private
RUN echo 'You found the secret file' > /home/user/svelte-app/build/private/secret.txt

# start server by default
WORKDIR /home/user/src
EXPOSE 9999
CMD ./server -p 9999 -R ../svelte-app/build -a
