#!/bin/bash
 
. /opt/ros/${ROS_DISTRO}/setup.sh
. /opt/conceptio/conceptio_core/conceptio_interfaces/geographic_info/geographic_msgs/install/setup.sh
. /opt/conceptio/conceptio_core/conceptio_interfaces/install/setup.sh
. /opt/conceptio/conceptio_core/install/setup.sh
ros2 launch conceptio_core core.xml
