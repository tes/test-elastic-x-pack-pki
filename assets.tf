variable "version" {
  description = "Version of ES and Kibana to use"
  default     = "6.2.2"
}

variable "elastic_password" {
  description = "Default Elasticsearch password"
  default     = "changeme"
}

# Root CA
resource "tls_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P521"
}

resource "tls_self_signed_cert" "ca" {
  key_algorithm   = "${tls_private_key.ca.algorithm}"
  private_key_pem = "${tls_private_key.ca.private_key_pem}"

  subject {
    common_name  = "CA Root"
    organization = "Test Org"
  }

  is_ca_certificate     = true
  validity_period_hours = 87600
  early_renewal_hours   = 2160

  allowed_uses = [
    "cert_signing",
  ]
}

# Intermediate CA
resource "tls_private_key" "intermediate_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P521"
}

resource "tls_cert_request" "intermediate_ca" {
  key_algorithm   = "${tls_private_key.intermediate_ca.algorithm}"
  private_key_pem = "${tls_private_key.intermediate_ca.private_key_pem}"

  subject {
    common_name         = "CA Intermediate"
    organization        = "Test Org"
    organizational_unit = "Elastic X-Pack"
  }
}

resource "tls_locally_signed_cert" "intermediate_ca" {
  cert_request_pem   = "${tls_cert_request.intermediate_ca.cert_request_pem}"
  ca_key_algorithm   = "${tls_private_key.ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.ca.private_key_pem}"
  ca_cert_pem        = "${tls_self_signed_cert.ca.cert_pem}"

  is_ca_certificate     = true
  validity_period_hours = 87600
  early_renewal_hours   = 2160

  allowed_uses = [
    "cert_signing",
  ]
}

# Elasticsearch
resource "tls_private_key" "elasticsearch_server" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "elasticsearch_server" {
  key_algorithm   = "${tls_private_key.elasticsearch_server.algorithm}"
  private_key_pem = "${tls_private_key.elasticsearch_server.private_key_pem}"

  subject {
    common_name  = "elasticsearch"
    organization = "elasticsearch"
  }

  dns_names = ["${concat(
    list(
      "localhost",
      "elasticsearch",
    ))}"]

  ip_addresses = [
    "127.0.0.1",
  ]
}

resource "tls_locally_signed_cert" "elasticsearch_server" {
  cert_request_pem = "${tls_cert_request.elasticsearch_server.cert_request_pem}"

  ca_key_algorithm   = "${tls_private_key.intermediate_ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.intermediate_ca.private_key_pem}"
  ca_cert_pem        = "${tls_locally_signed_cert.intermediate_ca.cert_pem}"

  validity_period_hours = 8760
  early_renewal_hours   = 2160

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
    "server_auth",
  ]
}

# Kibana
resource "tls_private_key" "elasticsearch_kibana_client" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "elasticsearch_kibana_client" {
  key_algorithm   = "${tls_private_key.elasticsearch_kibana_client.algorithm}"
  private_key_pem = "${tls_private_key.elasticsearch_kibana_client.private_key_pem}"

  subject {
    common_name  = "kibana"
    organization = "elasticsearch"
  }
}

resource "tls_locally_signed_cert" "elasticsearch_kibana_client" {
  cert_request_pem = "${tls_cert_request.elasticsearch_kibana_client.cert_request_pem}"

  ca_key_algorithm   = "${tls_private_key.intermediate_ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.intermediate_ca.private_key_pem}"
  ca_cert_pem        = "${tls_locally_signed_cert.intermediate_ca.cert_pem}"

  validity_period_hours = 8760
  early_renewal_hours   = 2160

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
    "server_auth",
  ]
}

# Metricbeat
resource "tls_private_key" "metricbeat_client_key" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "metricbeat_client_req" {
  key_algorithm   = "${tls_private_key.metricbeat_client_key.algorithm}"
  private_key_pem = "${tls_private_key.metricbeat_client_key.private_key_pem}"

  subject {
    common_name  = "metricbeat"
    organization = "elasticsearch"
  }
}

resource "tls_locally_signed_cert" "metricbeat_client_cert" {
  cert_request_pem = "${tls_cert_request.metricbeat_client_req.cert_request_pem}"

  ca_key_algorithm   = "${tls_private_key.intermediate_ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.intermediate_ca.private_key_pem}"
  ca_cert_pem        = "${tls_locally_signed_cert.intermediate_ca.cert_pem}"

  validity_period_hours = 8760
  early_renewal_hours   = 2160

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
}

# Generating assets as files
locals {
  ca_cert_chain_pem = "${join("\n", list(
      tls_locally_signed_cert.intermediate_ca.cert_pem,
      tls_self_signed_cert.ca.cert_pem,
    ))}"

  config_id = "${md5(join("", list(
      tls_locally_signed_cert.intermediate_ca.cert_pem,
      tls_self_signed_cert.ca.cert_pem,
      tls_locally_signed_cert.elasticsearch_server.cert_pem,
      tls_locally_signed_cert.elasticsearch_kibana_client.cert_pem,
    )))}"
}

# Elasticsearch
resource "local_file" "ssl_elasticsearch_ca_crt" {
  content  = "${local.ca_cert_chain_pem}"
  filename = "${path.module}/ssl/elasticsearch/ca.crt"
}

resource "local_file" "ssl_elasticsearch_server_crt" {
  content  = "${tls_locally_signed_cert.elasticsearch_server.cert_pem}"
  filename = "${path.module}/ssl/elasticsearch/server.crt"
}

resource "local_file" "ssl_elasticsearch_server_key" {
  content  = "${tls_private_key.elasticsearch_server.private_key_pem}"
  filename = "${path.module}/ssl/elasticsearch/server.key"
}

# Kibana
resource "local_file" "ssl_kibana_ca_crt" {
  content  = "${local.ca_cert_chain_pem}"
  filename = "${path.module}/ssl/kibana/ca.crt"
}

resource "local_file" "ssl_kibana_client_crt" {
  content  = "${tls_locally_signed_cert.elasticsearch_kibana_client.cert_pem}"
  filename = "${path.module}/ssl/kibana/client.crt"
}

resource "local_file" "ssl_kibana_client_key" {
  content  = "${tls_private_key.elasticsearch_kibana_client.private_key_pem}"
  filename = "${path.module}/ssl/kibana/client.key"
}

# Metricbeat
resource "local_file" "ssl_metricbeat_ca_crt" {
  content  = "${local.ca_cert_chain_pem}"
  filename = "${path.module}/ssl/metricbeat/ca.crt"
}

resource "local_file" "ssl_metricbeat_client_crt" {
  content  = "${tls_locally_signed_cert.metricbeat_client_cert.cert_pem}"
  filename = "${path.module}/ssl/metricbeat/client.crt"
}

resource "local_file" "ssl_metricbeat_client_key" {
  content  = "${tls_private_key.metricbeat_client_key.private_key_pem}"
  filename = "${path.module}/ssl/metricbeat/client.key"
}

resource "local_file" "metricbeat_yml" {
  content = <<EOF
metricbeat.config.modules:
  # Glob pattern for configuration loading
  path: $${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: true

  # Period on which files under path should be checked for changes
  reload.period: 10s

name: metricbeat

fields:
  environment: local

processors:
- add_cloud_metadata: ~

setup.kibana.host: "http://kibana:5601"
setup.kibana.username: elastic
setup.kibana.password: "${var.elastic_password}"

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]
  ssl.certificate: "/etc/pki/client.crt"
  ssl.key: "/etc/pki/client.key"
  ssl.supported_protocols: ["TLSv1.2"]
  ssl.verification_mode: full
  enabled: true
EOF

  filename = "${path.module}/assets/metricbeat.yml"
}

resource "local_file" "docker_compose_yml" {
  content = <<EOF
version: '3.3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${var.version}
    volumes:
      - ./ssl/elasticsearch:/etc/ssl/elasticsearch
      - ./assets/java.policy:/usr/share/elasticsearch/java.policy
      - ./assets/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
      - ./assets/roles.yml:/usr/share/elasticsearch/config/x-pack/roles.yml:ro
      - ./assets/role_mapping.yml:/usr/share/elasticsearch/config/x-pack/role_mapping.yml:ro
      - elasticsearch-data:/usr/share/elasticsearch/data
    environment:
      __CONFIG_ID: "${local.config_id}"
      ELASTIC_PASSWORD: "${var.elastic_password}"
      ES_JAVA_OPTS: "-Djava.security.policy=/usr/share/elasticsearch/java.policy"
      "discovery.type": "single-node"
    ports:
      - 9200:9200
    ulimits:
      nproc: 4096
      nofile:
        soft: 65536
        hard: 65536
      memlock:
        soft: -1
        hard: -1
    networks:
      - elastic-x-pack
  kibana:
    image: docker.elastic.co/kibana/kibana:${var.version}
    volumes:
      - ./ssl/kibana:/etc/ssl/kibana
    environment:
      __CONFIG_ID: "${local.config_id}"
      ELASTICSEARCH_URL: https://elasticsearch:9200
      ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES: /etc/ssl/kibana/ca.crt
      ELASTICSEARCH_SSL_CERTIFICATE: /etc/ssl/kibana/client.crt
      ELASTICSEARCH_SSL_KEY: /etc/ssl/kibana/client.key
      ELASTICSEARCH_SSL_VERIFICATIONMODE: full
    ports:
      - 5601:5601
    networks:
      - elastic-x-pack
  metricbeat:
    image: docker.elastic.co/beats/metricbeat:${var.version}
    volumes:
      - ./ssl/metricbeat:/etc/pki:ro
      - ./assets/metricbeat.yml:/usr/share/metricbeat/metricbeat.yml:ro
      - ./assets/modules.d:/usr/share/metricbeat/modules.d:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    user: root
    networks:
      - elastic-x-pack
volumes:
  elasticsearch-data: {}
networks:
  elastic-x-pack:
EOF

  filename = "${path.module}/docker-compose.yml"
}
