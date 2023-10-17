/*
ika-rwth-aachen/mqtt_client:
==============================================================================
MIT License

Copyright 2022 Institute for Automotive Engineering of RWTH Aachen University.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================
*/
#include "conceptio_core/entity_management.hpp"

#include "rclcpp_components/register_node_macro.hpp"
RCLCPP_COMPONENTS_REGISTER_NODE(EntityManagementNode)

EntityManagementNode::EntityManagementNode(const rclcpp::NodeOptions& options = rclcpp::NodeOptions()) : Node("entity_management_node", options)
{
    entity_updater_pub = this->create_publisher<conceptio_interfaces::msg::ArenaEntities>("arena_entities", 10);
    entity_list_srv = this->create_service<conceptio_interfaces::srv::RequestArenaEntityList>("request_arena_entity_list", 
        std::bind(&EntityManagementNode::entity_list_srv_callback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    
    
    mqtt_client = std::make_shared<MqttClient>();
    forward_parameters_to_mqtt(*mqtt_client);
    if (!mqtt_client->setup_mqtt_client()) {
        RCLCPP_ERROR(get_logger(), "Failed to setup MQTT client");
        return;
    }
    if (!mqtt_client->connect_mqtt_client()) {
        RCLCPP_ERROR(get_logger(), "Failed to connect MQTT client");
        return;
    }
    RCLCPP_INFO(get_logger(), "Successfully connected to MQTT broker");
    mqtt_client->entity_node = this;
    entity_check_timer = this->create_wall_timer(std::chrono::seconds(15), std::bind(&EntityManagementNode::check_entities, this));


}
EntityManagementNode::~EntityManagementNode()
{


}

void EntityManagementNode::check_entities(){
    // TODO: move to node parameter instead of const
    constexpr int64_t heartbeat_timeout_nanoseconds = 15000000;
    auto now = get_clock()->now().nanoseconds();
    for(auto& entity : entity_map){
        if(entity.second.last_heartbeat > now + heartbeat_timeout_nanoseconds){
           delete_entity(entity);
        }
    }

}

void EntityManagementNode::entity_list_srv_callback(
    const std::shared_ptr<rmw_request_id_t> request_header,
    const std::shared_ptr<conceptio_interfaces::srv::RequestArenaEntityList::Request> request,
    const std::shared_ptr<conceptio_interfaces::srv::RequestArenaEntityList::Response> response)
{
    (void)request_header;
    (void)request;
    //for(auto& entity : entity_map){
    //    response->entity_list.push_back(entity.second);
    //}

   
}

void EntityManagementNode::delete_entity(std::pair<std::string, Entity> entity){
    conceptio_interfaces::msg::ArenaEntities arena_entity;
    arena_entity.entity_name = entity.second.entity_name;
    arena_entity.entity_uuid = entity.second.entity_uuid; 
    arena_entity.is_alive = false;
    entity_updater_pub->publish(arena_entity);
    entity_map.erase(entity.first);
}



std::filesystem::path EntityManagementNode::resolvePath(const std::string& path_string) {

  std::filesystem::path path(path_string);
  if (path_string.empty()) return path;
  if (!path.has_root_path()) {
    std::string ros_home = rcpputils::get_env_var("ROS_HOME");
    if (ros_home.empty())
      ros_home = std::string(std::filesystem::current_path());
    path = std::filesystem::path(ros_home);
    path.append(path_string);
  }
  if (!std::filesystem::exists(path))
    RCLCPP_WARN(get_logger(), "Requested path '%s' does not exist",
                std::string(path).c_str());
  return path;
}

void EntityManagementNode::forward_parameters_to_mqtt(MqttClient &mqtt_client)
{
  rcl_interfaces::msg::ParameterDescriptor param_desc;

  param_desc.description = "IP address or hostname of the machine running the MQTT broker";
  declare_parameter("broker.host", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "port the MQTT broker is listening on";
  declare_parameter("broker.port", rclcpp::ParameterType::PARAMETER_INTEGER, param_desc);
  param_desc.description = "username used for authenticating to the broker (if empty, will try to connect anonymously)";
  declare_parameter("broker.user", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "password used for authenticating to the broker";
  declare_parameter("broker.pass", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "whether to connect via SSL/TLS";
  declare_parameter("broker.tls.enabled", rclcpp::ParameterType::PARAMETER_BOOL, param_desc);
  param_desc.description = "CA certificate file trusted by client (relative to ROS_HOME)";
  declare_parameter("broker.tls.ca_certificate", rclcpp::ParameterType::PARAMETER_STRING, param_desc);

  param_desc.description = "unique ID used to identify the client (broker may allow empty ID and automatically generate one)";
  declare_parameter("client.id", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "maximum number of messages buffered by the bridge when not connected to broker (only available if client ID is not empty)";
  declare_parameter("client.buffer.size", rclcpp::ParameterType::PARAMETER_INTEGER, param_desc);
  param_desc.description = "directory used to buffer messages when not connected to broker (relative to ROS_HOME)";
  declare_parameter("client.buffer.directory", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "topic used for this client's last-will message (no last will, if not specified)";
  declare_parameter("client.last_will.topic", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "last-will message";
  declare_parameter("client.last_will.message", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "QoS value for last-will message";
  declare_parameter("client.last_will.qos", rclcpp::ParameterType::PARAMETER_INTEGER, param_desc);
  param_desc.description = "whether to retain last-will message";
  declare_parameter("client.last_will.retained", rclcpp::ParameterType::PARAMETER_BOOL, param_desc);
  param_desc.description = "whether to use a clean session for this client";
  declare_parameter("client.clean_session", rclcpp::ParameterType::PARAMETER_BOOL, param_desc);
  param_desc.description = "keep-alive interval in seconds";
  declare_parameter("client.keep_alive_interval", rclcpp::ParameterType::PARAMETER_DOUBLE, param_desc);
  param_desc.description = "maximum number of inflight messages";
  declare_parameter("client.max_inflight", rclcpp::ParameterType::PARAMETER_INTEGER, param_desc);
  param_desc.description = "client certificate file (only needed if broker requires client certificates; relative to ROS_HOME)";
  declare_parameter("client.tls.certificate", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "client private key file (relative to ROS_HOME)";
  declare_parameter("client.tls.key", rclcpp::ParameterType::PARAMETER_STRING, param_desc);
  param_desc.description = "client private key password";
  declare_parameter("client.tls.password", rclcpp::ParameterType::PARAMETER_STRING, param_desc);

  // load broker parameters from parameter server
  std::string broker_tls_ca_certificate;
  loadParameter<std::string>("broker.host", mqtt_client.broker_config_.host, "localhost");
  loadParameter<int>("broker.port", mqtt_client.broker_config_.port, 1883);
  if (loadParameter<std::string>("broker.user", mqtt_client.broker_config_.user)) {
    loadParameter<std::string>("broker.pass", mqtt_client.broker_config_.pass, "");
  }
  if (loadParameter<bool>("broker.tls.enabled", mqtt_client.broker_config_.tls.enabled, false)) {
    loadParameter<std::string>("broker.tls.ca_certificate", broker_tls_ca_certificate,
                  "/etc/ssl/certs/ca-certificates.crt");
  }

  // load client parameters from parameter server
  std::string client_buffer_directory, client_tls_certificate, client_tls_key;
  loadParameter<std::string>("client.id", mqtt_client.client_config_.id, "");
  mqtt_client.client_config_.buffer.enabled = !mqtt_client.client_config_.id.empty();
  if (mqtt_client.client_config_.buffer.enabled) {
    loadParameter<int>("client.buffer.size", mqtt_client.client_config_.buffer.size, 0);
    loadParameter<std::string>("client.buffer.directory", client_buffer_directory, "buffer");
  } else {
    RCLCPP_WARN(get_logger(),
                "Client buffer can not be enabled when client ID is empty");
  }
  if (loadParameter<std::string>("client.last_will.topic", mqtt_client.client_config_.last_will.topic)) {
    loadParameter<std::string>("client.last_will.message", mqtt_client.client_config_.last_will.message,
                  "offline");
    loadParameter<int>("client.last_will.qos", mqtt_client.client_config_.last_will.qos, 0);
    loadParameter<bool>("client.last_will.retained",
                  mqtt_client.client_config_.last_will.retained, false);
  }
  loadParameter<bool>("client.clean_session", mqtt_client.client_config_.clean_session, true);
  loadParameter<double>("client.keep_alive_interval",
                 mqtt_client.client_config_.keep_alive_interval, 60.0);
  loadParameter<int>("client.max_inflight",  mqtt_client.client_config_.max_inflight, 65535);
  if (mqtt_client.broker_config_.tls.enabled) {
    if (loadParameter<std::string>("client.tls.certificate", client_tls_certificate)) {
      loadParameter<std::string>("client.tls.key", client_tls_key);
      loadParameter<std::string>("client.tls.password",  mqtt_client.client_config_.tls.password);
      loadParameter<int>("client.tls.version",  mqtt_client.client_config_.tls.version);
      loadParameter<bool>("client.tls.verify",  mqtt_client.client_config_.tls.verify);
      loadParameter<std::vector<std::string>>("client.tls.alpn_protos",  mqtt_client.client_config_.tls.alpn_protos);
    }
  }
  // resolve filepaths
  mqtt_client.broker_config_.tls.ca_certificate = resolvePath(broker_tls_ca_certificate);
  mqtt_client.client_config_.buffer.directory = resolvePath(client_buffer_directory);
  mqtt_client.client_config_.tls.certificate = resolvePath(client_tls_certificate);
  mqtt_client.client_config_.tls.key = resolvePath(client_tls_key);



}

void EntityManagementNode::publish_entity_update(Entity &entity)
{
    conceptio_interfaces::msg::ArenaEntities arena_entity;
    arena_entity.entity_name = entity.entity_name;
    arena_entity.entity_uuid = entity.entity_uuid; 
    arena_entity.is_alive = true;

    entity_updater_pub->publish(arena_entity);
}

MqttClient::MqttClient(){

}

MqttClient::~MqttClient(){

}


bool MqttClient::setup_mqtt_client()
{
  mqtt_conn_options.set_automatic_reconnect(true);
  mqtt_conn_options.set_clean_session(client_config_.clean_session);
  mqtt_conn_options.set_keep_alive_interval(client_config_.keep_alive_interval);
  mqtt_conn_options.set_max_inflight(client_config_.max_inflight);

  // user authentication
  if (!broker_config_.user.empty()) {
    mqtt_conn_options.set_user_name(broker_config_.user);
    mqtt_conn_options.set_password(broker_config_.pass);
  }

  // last will
  if (!client_config_.last_will.topic.empty()) {
    mqtt::will_options will(
      client_config_.last_will.topic, client_config_.last_will.message,
      client_config_.last_will.qos, client_config_.last_will.retained);
    mqtt_conn_options.set_will(will);
  }

  // SSL/TLS
  if (broker_config_.tls.enabled) {
    mqtt::ssl_options ssl;
    ssl.set_trust_store(broker_config_.tls.ca_certificate);
    if (!client_config_.tls.certificate.empty() &&
        !client_config_.tls.key.empty()) {
      ssl.set_key_store(client_config_.tls.certificate);
      ssl.set_private_key(client_config_.tls.key);
      if (!client_config_.tls.password.empty())
        ssl.set_private_key_password(client_config_.tls.password);
    }
    ssl.set_ssl_version(client_config_.tls.version);
    ssl.set_verify(client_config_.tls.verify);
    ssl.set_alpn_protos(client_config_.tls.alpn_protos);
    mqtt_conn_options.set_ssl(ssl);
  }

  // create MQTT client
  const std::string protocol = broker_config_.tls.enabled ? "ssl" : "tcp";
  const std::string uri = fmt::format("{}://{}:{}", protocol, broker_config_.host,
                                      broker_config_.port);
  try {
    if (client_config_.buffer.enabled) {
      client_ = std::shared_ptr<mqtt::async_client>(new mqtt::async_client(
        uri, client_config_.id, client_config_.buffer.size,
        client_config_.buffer.directory));
    } else {
      client_ = std::shared_ptr<mqtt::async_client>(
        new mqtt::async_client(uri, client_config_.id));
    }
  } catch (const mqtt::exception& e) {
    std::cout << "Client could not be initialized: " << e.what() << std::endl;
    return false;
  }
  // setup MQTT callbacks
  client_->set_callback(*this);
  return true;
}


bool MqttClient::connect_mqtt_client(){
  std::string as_client =
    client_config_.id.empty()
      ? ""
      : std::string(" as '") + client_config_.id + std::string("'");
  std::cout << "Connecting to broker at " <<
              client_->get_server_uri().c_str() << " " <<  as_client.c_str() << std::endl;

  try {
    client_->connect(mqtt_conn_options, nullptr, *this);
  } catch (const mqtt::exception& e) {
    std::cout << "Connection to broker failed: " << e.what() << std::endl;
    return false;
  }

  return true;
}

void MqttClient::connected(const std::string& cause)
{
  is_connected_ = true;
  std::cout << "Connected to broker: " << cause << std::endl;
  // subscribe to heartbeats
  client_->subscribe("/conceptio/unit/+/+/+/heartbeat", 1);
}

void MqttClient::connection_lost(const std::string& cause)
{
  is_connected_ = false;
  std::cout << "Connection lost: " << cause << std::endl;
  std::cout << "Attempting to reconnect..." << std::endl;
  connect_mqtt_client();
}


void MqttClient::on_success(const mqtt::token& tok)
{
  std::cout << "Success" << std::endl;
}

void MqttClient::on_failure(const mqtt::token& tok)
{
  std::cout << "Failure" << std::endl;
}

void MqttClient::delivery_complete(mqtt::delivery_token_ptr token)
{
  std::cout << "Delivery complete" << std::endl;
}


void MqttClient::message_arrived(mqtt::const_message_ptr mqtt_msg){
  // instantly take arrival timestamp
  rclcpp::Time arrival_stamp(
    builtin_interfaces::msg::Time(rclcpp::Clock(RCL_SYSTEM_TIME).now()));

  std::string mqtt_topic = mqtt_msg->get_topic();
  std::cout << "Message arrived on topic '" << mqtt_topic << "'" << std::endl;
  size_t lastSlashPos = mqtt_topic.find_last_of('/');
  std::string last_topic = lastSlashPos!=std::string::npos?mqtt_topic.substr(lastSlashPos+1):"";
  auto& payload = mqtt_msg->get_payload_ref();

  // Parse payload as JSON
  rapidjson::Document doc;
  try {
    doc.Parse(payload.c_str());
  } catch (std::exception &e) {
    std::cout << "Failed to parse payload as JSON: " << e.what() << std::endl;
    return;
  }
  if(entity_node){
    if(last_topic == "heartbeat"){
      EntityManagementNode::Entity& entity = entity_node->entity_map[mqtt_topic];
      entity.entity_name =doc["entity_name"].GetString();
      entity.entity_type = static_cast<EntityManagementNode::EntityType>\
        (doc["entity_type"].GetInt());
      entity.entity_uuid = doc["entity_uuid"].GetString();
      entity.entity_domain = static_cast<EntityManagementNode::EntityDomain>\
        (doc["entity_domain"].GetInt());
      entity.last_heartbeat = entity_node->get_clock()->now().nanoseconds();
      entity_node->publish_entity_update(entity);
    }
  }
}

int main (int argc, char* argv[]){
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<EntityManagementNode>());
  rclcpp::shutdown();
  return 0;
}