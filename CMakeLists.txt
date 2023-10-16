cmake_minimum_required(VERSION 3.8)
project(conceptio_core)

find_package(ros_environment REQUIRED QUIET)

# set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
add_compile_options(-std=c++17)
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# include directories
include_directories(include)

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(rclcpp_components REQUIRED)
find_package(conceptio_interfaces REQUIRED)
find_package(fmt REQUIRED)
find_package(RapidJSON REQUIRED)
find_library(PahoMqttC_LIBRARY libpaho-mqtt3as.so.1 REQUIRED)
find_library(PahoMqttCpp_LIBRARY libpaho-mqttpp3.so.1 REQUIRED)

# uncomment the following section in order to fill in
# further dependencies manually.
# find_package(<dependency> REQUIRED)

# add source files
add_library(entity_management src/entity_management.cpp)

# set include directories for the target
target_include_directories(entity_management PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)


target_link_libraries(entity_management
    ${PahoMqttC_LIBRARY}
    ${PahoMqttCpp_LIBRARY}
  )

# set libraries for the target
ament_target_dependencies(entity_management
  rclcpp_components
  fmt
  rclcpp
  RapidJSON
  conceptio_interfaces
)

# set compile features for the target
target_compile_features(entity_management PUBLIC c_std_99 cxx_std_17)  # Require C99 and C++17

# install target
install(TARGETS entity_management
  DESTINATION lib/${PROJECT_NAME})

# enable testing
if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  # the following line skips the linter which checks for copyrights
  # comment the line when a copyright and license is added to all source files
  set(ament_cmake_copyrighT_FOUND TRUE)
  # the following line skips cpplint (only works in a git repo)
  # comment the line when this package is in a git repo and when
  # a copyright and license is added to all source files
  set(ament_cmake_cpplint_FOUND TRUE)
  ament_lint_auto_find_test_dependencies()
endif()

ament_package()
