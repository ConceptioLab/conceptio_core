ARG ROS_DISTRO=humble
FROM ros:${ROS_DISTRO} as builder

ARG WORKSPACE=/opt/conceptio

RUN apt update -y && apt dist-upgrade -y && apt install -y python3-pip ufw libpaho-mqtt-dev libpaho-mqttpp-dev


WORKDIR ${WORKSPACE}
COPY [".", "${WORKSPACE}/conceptio_core/"]
ARG DEBIAN_FRONTEND=noninteractive


WORKDIR ${WORKSPACE}/conceptio_core
RUN pip3 install --upgrade setuptools==58.2.0

RUN rosdep install --from-paths . --ignore-src -r -y

WORKDIR ${WORKSPACE}/conceptio_core/conceptio_interfaces/geographic_info/geographic_msgs
RUN . /opt/ros/${ROS_DISTRO}/setup.sh && \
	colcon build

WORKDIR ${WORKSPACE}/conceptio_core/conceptio_interfaces
RUN . /opt/ros/${ROS_DISTRO}/setup.sh && \
	. /opt/conceptio/conceptio_core/conceptio_interfaces/geographic_info/geographic_msgs/install/setup.sh && \
	colcon build

WORKDIR ${WORKSPACE}/conceptio_core
RUN . /opt/ros/${ROS_DISTRO}/setup.sh && \
	. /opt/conceptio/conceptio_core/conceptio_interfaces/geographic_info/geographic_msgs/install/setup.sh && \
	. /opt/conceptio/conceptio_core/conceptio_interfaces/install/setup.sh && \
	colcon build
	
HEALTHCHECK --interval=10s --timeout=4s \
	CMD ./healthcheck.sh 

RUN ["chmod", "+x", "dockerfiles/entrypoint.sh"]
RUN ["chmod", "+x", "dockerfiles/healthcheck.sh"]
ENTRYPOINT ./dockerfiles/entrypoint.sh


