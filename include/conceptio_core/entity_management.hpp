#include "rclcpp/rclcpp.hpp"
#include "conceptio_interfaces/msg/arena_entities.hpp"
#include "conceptio_interfaces/srv/request_arena_entity_list.hpp"
#include <mqtt/async_client.h>
#include <filesystem>
#include <rcpputils/env.hpp>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <rapidjson/document.h>

class MqttClient;
class EntityManagementNode;

class EntityManagementNode : public rclcpp::Node
{
friend class MqttClient;
    public:

    enum EntityType{
        REAL,
        VIRTUAL,
        MODEL
    };

    enum EntityDomain{
        OTHER,
        LAND,
        AIR,
        SURFACE,
        SUBSURFACE,
        SPACE
    };

    struct Entity{
        std::string entity_name;
        std::string entity_uuid;
        std::string entity_visual_definition;
        EntityType entity_type;
        EntityDomain entity_domain;
        int64_t last_heartbeat;         // Last epoch-based timestamp in nanoseconds
    };

    EntityManagementNode(const rclcpp::NodeOptions& options);
    ~EntityManagementNode();

    template <typename T>
    bool loadParameter(const std::string& key, T& value) {
        bool found = get_parameter(key, value);
        bool is_numeric = std::is_arithmetic<T>::value;
        //if (found && is_numeric)
            //RCLCPP_DEBUG(get_logger(), "Retrieved parameter '%s' = '%s'", key.c_str(),
            //    std::to_string(value).c_str());
        //else
            //RCLCPP_DEBUG(get_logger(), "Retrieved parameter '%s' = '%s'", key.c_str(),
             //   value);
        return found;
    }
    template <typename T>
    bool loadParameter(const std::string& key, T& value,
                            const T& default_value) {
        bool found = get_parameter_or(key, value, default_value);
        if (!found){
            constexpr bool is_numeric = std::is_arithmetic<T>::value;
            if(is_numeric){
                //RCLCPP_WARN(get_logger(), "Parameter '%s' not set, defaulting to '%s'",
                //key.c_str(), std::to_string(default_value).c_str());
            }
            else{
                //RCLCPP_WARN(get_logger(), "Parameter '%s' not set, defaulting to '%s'",
                //key.c_str(), default_value);
            }
        }
        if (found){
            bool is_numeric = std::is_arithmetic<T>::value;
            //if(is_numeric)
                //RCLCPP_DEBUG(get_logger(), "Retrieved parameter '%s' = '%s'", key.c_str(),
                //    std::to_string(value).c_str());
            //else
                //RCLCPP_DEBUG(get_logger(), "Retrieved parameter '%s' = '%s'", key.c_str(),
                 //   value);
        }
    return found;
    }

    void publish_entity_update(Entity& entity);
    std::filesystem::path resolvePath(const std::string& path_string);
    void forward_parameters_to_mqtt(MqttClient& mqtt_client);
    void check_entities();
    void delete_entity(std::pair<std::string, Entity> entity);

    protected:
    void entity_list_srv_callback(
        const std::shared_ptr<rmw_request_id_t> request_header,
        const std::shared_ptr<conceptio_interfaces::srv::RequestArenaEntityList::Request> request,
        const std::shared_ptr<conceptio_interfaces::srv::RequestArenaEntityList::Response> response);

    std::unordered_map<std::string, Entity> entity_map;

    rclcpp::Publisher<conceptio_interfaces::msg::ArenaEntities>\
    ::SharedPtr entity_updater_pub;
    rclcpp::Service<conceptio_interfaces::srv::RequestArenaEntityList>\
    ::SharedPtr entity_list_srv;
    rclcpp::TimerBase::SharedPtr entity_check_timer;

    std::shared_ptr<MqttClient> mqtt_client;

};



class MqttClient : public virtual mqtt::callback,
                   public virtual mqtt::iaction_listener
{
friend class EntityManagementNode;
public:
        MqttClient();
        ~MqttClient();

        
        bool setup_mqtt_client();
        bool connect_mqtt_client();
        void connected(const std::string& cause) override;
        void connection_lost(const std::string& cause) override;
        void message_arrived(mqtt::const_message_ptr msg) override;
        void delivery_complete(mqtt::delivery_token_ptr token) override;
        void on_failure(const mqtt::token& tok) override;
        void on_success(const mqtt::token& tok) override;


protected:

struct BrokerConfig {
        std::string host;  ///< broker host
        int port;          ///< broker port
        std::string user;  ///< username
        std::string pass;  ///< password
        struct {
        bool enabled;  ///< whether to connect via SSL/TLS
        std::filesystem::path
            ca_certificate;  ///< public CA certificate trusted by client
        } tls;               ///< SSL/TLS-related variables
    };

struct ClientConfig {
        std::string id;  ///< client unique ID
        struct {
            bool enabled;                     ///< whether client buffer is enabled
            int size;                         ///< client buffer size
            std::filesystem::path directory;  ///< client buffer directory
        } buffer;                           ///< client buffer-related variables
        struct {
            std::string topic;         ///< last-will topic
            std::string message;       ///< last-will message
            int qos;                   ///< last-will QoS value
            bool retained;             ///< whether last-will is retained
        } last_will;                 ///< last-will-related variables
        bool clean_session;          ///< whether client requests clean session
        double keep_alive_interval;  ///< keep-alive interval
        int max_inflight;            ///< maximum number of inflight messages
        struct {
            std::filesystem::path certificate;    ///< client certificate
            std::filesystem::path key;            ///< client private keyfile
            std::string password;                 ///< decryption password for private key
        int version;                          ///< TLS version (https://github.com/eclipse/paho.mqtt.cpp/blob/master/src/mqtt/ssl_options.h#L305)
        bool verify;                          ///< Verify the client should conduct
                                                ///< post-connect checks
        std::vector<std::string> alpn_protos; ///< list of ALPN protocols
        } tls;                   ///< SSL/TLS-related variables
    };


    BrokerConfig broker_config_;
    ClientConfig client_config_;
    mqtt::connect_options mqtt_conn_options;
    std::shared_ptr<mqtt::async_client> client_;
    bool is_connected_;
    EntityManagementNode* entity_node;
};
