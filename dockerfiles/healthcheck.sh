#!/bin/bash

node_name_entity_management="/entity_management_node"
source /opt/ros/$ROS_DISTRO/setup.bash
node_list=$(ros2 node list)

if [[ "$node_list" == *"$node_name_entity_management"* ]]; then
    exit 0
else
    exit 1
fi

