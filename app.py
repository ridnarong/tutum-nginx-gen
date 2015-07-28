import os
import tutum
import websocket

webapps = {}

def has_virtual_host(envvars):
  for item in envvars:
    if item["key"] == "VIRTUAL_HOST":
      return item["value"]
  return None

def gen_conf(webapps):
  conf_txt = """gzip_types text/plain text/css application/javascript application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;
    log_format vhost '$host $remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent"';

    access_log /proc/self/fd/1 vhost;
    error_log /proc/self/fd/2;

    server {
    	listen 80;
    	server_name _; # This is just an invalid value which will never trigger on a real hostname.
    	return 503;
    }

"""

  for domain in webapps:
    outer_port = None
    service = webapps[domain]
    print service
    upstream = "upstream {0} {{ ".format(domain)
    for container_uuid in service['containers']:
      container = tutum.Container.fetch(container_uuid.split("/")[4])
      for port in container.container_ports:
        if port['inner_port'] == 80:
          outer_port = port['outer_port']
          break
      if outer_port:
        upstream += "server {0}:{1}; ".format(container.name,outer_port)
    upstream += "}}\n server {{\n listen 443 ssl;\n server_name {0};\n ".format(domain)
    upstream += "ssl_certificate {};\n".format(os.environ["SSL_CERT_PATH"])
    upstream += "ssl_certificate_key {};\n".format(os.environ["SSL_CERT_KEY_PATH"])
    upstream += "location / {{  \nproxy_pass http://{0}; \n}}\n}}\n".format(domain)
    conf_txt += upstream
  return conf_txt

def write_conf(conf):
  f = open(os.environ["CONF_PATH"], 'w')
  f.write(conf)
  f.close()

def restart_nginx():
  service = tutum.Service.fetch(os.environ["NGINX_1_ENV_TUTUM_SERVICE_API_URI"].split("/")[4])
  if service.state == "Running":
    for container_uuid in service.containers:
      endpoint = "container/%s/exec?" % container_uuid.split("/")[4]
      endpoint += "user=%s&token=%s" % (tutum.user, tutum.apikey)
      endpoint += "&command=%s" % urllib.quote_plus("kill -HUP 1")
      websocket.WebSocketApp('wss://stream.tutum.co/v1/'+endpoint)

def process_event(event):
  global webapps
  if event["type"] == "service":
    service = tutum.Service.fetch(event["resource_uri"].split("/")[4])
    domain = has_virtual_host(service.container_envvars)
    changed = False
    if domain:
      if service.state == "Running":
          webapps[domain] = {
            'name': service.name,
            'uuid': service.uuid,
            'containers': service.containers
          }
          changed = True
      elif service.state == "Stopped":
        if domain in webapps:
          webapps.pop(domain, None)
          changed = True
      if changed:
        write_conf(gen_conf(webapps))
        restart_nginx()

service = tutum.Service.list(state="Running")
for serv in service:
  service = tutum.Service.fetch(serv.resource_uri.split("/")[4])
  domain = has_virtual_host(service.container_envvars)
  if domain:
      webapps[domain] = {
        'name': service.name,
        'uuid': service.uuid,
        'containers': service.containers
      }
write_conf(gen_conf(webapps))
restart_nginx()

events = tutum.TutumEvents()
events.on_message(process_event)
events.run_forever()
