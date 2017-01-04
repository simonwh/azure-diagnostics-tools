#!/bin/bash

# The MIT License (MIT)
#
# Copyright (c) 2015 Microsoft Azure
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Error out if uninitialized variable is used
set -u  

usage()
{
    cat <<END
This script installs ElasticSearch on Ubuntu VM and makes it part of a specified ES cluster
Parameters:
  -n <ElasticSearch cluster name>
  -d <Static discovery endpoint start address> e.g. 10.0.1.4
  -c <Count of cluster nodes>
  -v <ElasticSearch version> e.g. 2.2.1
  -k <Kibana version> e.g. 4.1.1. 
  -u <ElasticSearch user name>
  -p <ElasticSearch user password>
  -s <ElasticSearch cluster DNS name> (to configure nginx proxy)
  -h view this help content
Elastic Search user name, user password and cluster DNS name are mandatory
END
}

# Usage: get_discovery_endpoints start_address node_count
# Example: get_discovery_endpoints 10.0.1.4 3
# (returns ["10.0.1.4", "10.0.1.5", "10.0.1.6"]
get_discovery_endpoints()
{
    declare start_address=$1
    declare address_prefix=${start_address%.*}     # Everything up to last dot (not including)
    declare -i address_suffix_start=${start_address##*.}  # Last part of the address, interpreted as a number
    declare retval='['
    declare -i i
    declare -i suffix
    
    for (( i=0; i<$2; ++i )); do
        suffix=$(( address_suffix_start + i ))
        retval+="\"${address_prefix}.${suffix}\", "
    done
    
    retval=${retval:0:-2}               # Remove last comma and space
    retval+=']'
    
    echo $retval
}

wait_for_elastic_svc()
{
    declare cluster_health=''
    declare -r HEALTHY='"status":"green"'
    declare -ri MAX_TRIES=30    # Keep trying for 5 minutes
    declare -i i=0

    until [[ $cluster_health =~ $HEALTHY || $i -eq $MAX_TRIES ]]; do
        sleep 10
        i+=1
        cluster_health=$(curl --max-time 10 -s http://localhost:9200/_cluster/health)
    done

    if [[ $i -eq $MAX_TRIES ]]; then
        return 1
    else
        return 0
    fi
}


if [ "${UID}" -ne 0 ];
then
    echo "You must be root to run this program." >&2
    exit 3
fi

echo "#################### Installing ElasticSearch on ${HOSTNAME} ####################"

cluster_name="kocour"
es_version="5.1.1"
kibana_version="5.1.1"
starting_discovery_endpoint="10.0.1.4"
declare -i cluster_node_count=3
es_user_name=''
es_user_password=''
es_dns_name=''
export DEBIAN_FRONTEND='noninteractive'

while getopts n:d:c:v:u:p:s:k:h optname; do    
  case $optname in
    n) 
      cluster_name=${OPTARG}
      ;;
    d) 
      starting_discovery_endpoint=${OPTARG}
      ;;
    c)
      cluster_node_count=${OPTARG}
      ;;
    v) 
      es_version=${OPTARG}
      ;;
    k)
      kibana_version=${OPTARG}
      ;;
    u)
      es_user_name=${OPTARG}
      ;;
    p)
      es_user_password=${OPTARG}
      ;;
    s)
      es_dns_name=${OPTARG}
      ;;
    h) 
      usage
      exit 1
      ;;
    \?) 
      echo "Unrecognized option $optname"
      usage
      exit 2
      ;;
  esac
done

if [[ ! $es_user_name || ! $es_user_password || ! es_dns_name ]]; then
    echo 'ElasticSearch user name, password, and server DNS name must be provided (not empty)'
    exit 3
fi

echo "#################### Installing Java ####################"
sudo apt-get update
sudo apt-get -qy install openjdk-8-jre
sudo update-ca-certificates -f

echo "#################### Setting up data disks ####################"
bash vm-disk-utils-0.1.sh

echo "#################### Installing ES service ####################"
sudo wget "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$es_version.deb" -O elasticsearch.deb
sudo dpkg -i --force-all elasticsearch.deb
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service

echo "#################### Configuring data disks for ES ####################"
datapath_config=""
if [ -d '/datadisks' ]; then
    for disk_id in `find /datadisks/ -mindepth 1 -maxdepth 1 -type d`
    do
        # Configure disk permissions and folder for storage
        # We rely on ES default user name & group (elasticsearch)
        mkdir -p "${disk_id}/elasticsearch/data"
        chown -R elasticsearch:elasticsearch "${disk_id}/elasticsearch"
        chmod 755 "${disk_id}/elasticsearch"
        # Add to list for elasticsearch configuration
        datapath_config+="${disk_id}/elasticsearch/data,"
    done
    #Remove the extra trailing comma
    datapath_config="${datapath_config%?}"
else
    echo "Data disk directory not found, cannot set up storage for ElasticSearch service"
    exit 4
fi

echo "#################### Configuring ES service ####################"
echo "cluster.name: $cluster_name" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: ${HOSTNAME}" >> /etc/elasticsearch/elasticsearch.yml
echo "gateway.expected_nodes: ${cluster_node_count}" >> /etc/elasticsearch/elasticsearch.yml
discovery_endpoints=$(get_discovery_endpoints $starting_discovery_endpoint $cluster_node_count)
echo "Setting ES discovery endpoints to $discovery_endpoints"
echo "discovery.zen.ping.unicast.hosts: $discovery_endpoints" >> /etc/elasticsearch/elasticsearch.yml
echo "path.data: $datapath_config" >> /etc/elasticsearch/elasticsearch.yml
declare -i minimum_master_nodes=$(((cluster_node_count / 2) + 1))
echo "discovery.zen.minimum_master_nodes: $minimum_master_nodes" >> /etc/elasticsearch/elasticsearch.yml
echo "gateway.recover_after_time: 1m" >> /etc/elasticsearch/elasticsearch.yml
echo "bootstrap.memory_lock: true" >> /etc/elasticsearch/elasticsearch.yml
echo "node.master: true" >> /etc/elasticsearch/elasticsearch.yml
echo "node.data: true" >> /etc/elasticsearch/elasticsearch.yml
echo "network.host: [_site_, _local_]" >> /etc/elasticsearch/elasticsearch.yml

echo "#################### Installing nginx ####################"
sudo apt-get -qy install nginx
sudo systemctl daemon-reload
sudo systemctl enable nginx

echo "#################### Configuring nginx ####################"
sudo apt-get -qy install apache2-utils
printf '%s' "$es_user_password" | sudo htpasswd -ic /etc/nginx/conf.d/elasticsearch.pwd $es_user_name
config_fetch_cmd='curl -s https://raw.githubusercontent.com/Azure/azure-diagnostics-tools/dev/karolz/es-5/ES-MultiNode/elasticsearch.nginx | perl -wnlp -e s/__ES_DNS_NAME/'
config_fetch_cmd+="$es_dns_name"
config_fetch_cmd+='/g > elasticsearch.nginx.conf'
eval "$config_fetch_cmd"
sudo cp elasticsearch.nginx.conf /etc/nginx/sites-available/elasticsearch
sudo ln /etc/nginx/sites-available/elasticsearch /etc/nginx/sites-enabled
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl reload nginx


echo "#################### Installing Kibana ####################"
sudo wget "https://artifacts.elastic.co/downloads/kibana/kibana-${kibana_version}-linux-x86_64.tar.gz"
sudo tar xvf kibana-*.tar.gz 1>/dev/null
sudo mkdir -p /opt/kibana
sudo cp -R ./kibana-5*/* /opt/kibana
sudo wget https://raw.githubusercontent.com/Azure/azure-diagnostics-tools/dev/karolz/es-5/ES-MultiNode/kibana5.service
sudo cp ./kibana5.service /etc/systemd/system/kibana5.service
sudo systemctl daemon-reload
sudo systemctl enable kibana5.service
sudo mkdir -p /var/log/kibana
printf "\n\nlog_file: /var/log/kibana/kibana.log\n" | sudo tee -a /opt/kibana/config/kibana.yml > /dev/null
# ES can take a while to start up, so increase the Kibana startup timeout to 2 minutes
printf "startup_timeout: 120000\n" | sudo tee -a /opt/kibana/config/kibana.yml > /dev/null


echo "#################### Optimizing the system ####################"
# Set Elasticsearch heap size to 50% of system memory
# Consider: Move this to an init.d script so we can handle instance size increases
es_heap_size=$(free -m |grep Mem | awk '{if ($2/2 >31744)  print 31744;else print $2/2;}')
printf "\nES_HEAP_SIZE=%sm\n" $es_heap_size | sudo tee -a /etc/default/elasticseach > /dev/null
printf "MAX_LOCKED_MEMORY=unlimited\n" | sudo tee -a /etc/default/elasticsearch > /dev/null
printf "\nelasticsearch - nofile 65536" | sudo tee -a /etc/security/limits.conf > /dev/null
printf "\nelasticsearch  - memlock unlimited" | sudo tee -a /etc/security/limits.conf > /dev/null
sudo mkdir -p /etc/systemd/system/elasticsearch.service.d
printf "\n[Service]\nLimitMEMLOCK=infinity\n" | sudo tee -a /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf > /dev/null

echo "#################### Start Elasticsearch service ####################"
sudo systemctl start elasticsearch.service

wait_for_elastic_svc;
if [[ $? -ne 0 ]]; then
    echo "ElasticSearch service has not started within expected time period. Cannot start Kibana service or install ES head plugin." >&2
    exit 5
fi

echo "#################### Installing X-pack plugin ####################"
sudo /usr/share/elasticsearch/bin/elasticsearch-plugin --batch install x-pack

# Disable all features that require paid subscription
# Monitoring is left enabled--requires a free Basic License
sudo systemctl stop elasticsearch.service
printf "\nxpack.security.enabled: false\n" | sudo tee -a /etc/elasticsearch/elasticsearch.yml | sudo tee -a /opt/kibana/config/kibana.yml > /dev/null
printf "xpack.graph.enabled: false\n" | sudo tee -a /etc/elasticsearch/elasticsearch.yml | sudo tee -a /opt/kibana/config/kibana.yml > /dev/null
printf "xpack.watcher.enabled: false\n" | sudo tee -a /etc/elasticsearch/elasticsearch.yml > /dev/null
printf "xpack.reporting.enabled: false\n" | sudo tee -a /opt/kibana/config/kibana.yml > /dev/null

echo "#################### Restarting Elasticsearch and starting Kibana ####################"
sudo systemctl start elasticsearch.service
wait_for_elastic_svc;
sudo systemctl start kibana5.service

exit 0
