import os
import tutum

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

    # HTTP 1.1 support
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $proxy_connection;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;

    server {
    	listen 80;
    	server_name _; # This is just an invalid value which will never trigger on a real hostname.
    	return 503;
    };

    """

  for domain in webapps:
    upstream = "upstream {0} {{ ".format(domain)
    outer_port = None
    for server in webapps[domain]:
        print server
        for port in server['container_ports']:
          if port['inner_port'] == 80:
            outer_port = port['outer_port']
            break
        if outer_port:
          upstream += "server {0}:{1}; ".format(server['private_ip'],outer_port)
    upstream += "}}; server {{ listen 443 ssl; server_name {0}; ".format(domain)
    upstream += "ssl_certificate {}; ".format(os.environ["SSL_CERT_PATH"])
    upstream += "ssl_certificate_key {}; ".format(os.environ["SSL_CERT_KEY_PATH"])
    upstream += "location / {{ proxy_pass http://{0}; ".format(domain)
    upstream += " include /etc/nginx/proxy_params; }};"
    conf_txt += upstream
  return conf_txt

def write_conf(conf):
  f = open(os.environ["CONF_PATH"], 'w')
  f.write(conf)
  f.close()

def restart_nginx():
  container = tutum.Container.fetch(os.environ["NGINX_TUTUM_CONTAINER_API_URI"].split("/")[4])
  container.stop()
  container.start()

def process_event(event):
  global webapps
  if event["type"] == "container":
    container = tutum.Container.fetch(event["resource_uri"].split("/")[4])
    domain = has_virtual_host(container.container_envvars)
    changed = False
    if domain:
      if container.state == "Running":
        if domain in webapps:
          webapps[domain].append({
            'name': container.name,
            'node': container.node,
            'private_ip': container.private_ip,
            'public_dns': container.public_dns,
            'resource_uri': container.resource_uri,
            'container_ports': container.container_ports})
          changed = True
        else:
          webapps[domain] = [{
            'name': container.name,
            'node': container.node,
            'private_ip': container.private_ip,
            'public_dns': container.public_dns,
            'resource_uri': container.resource_uri,
            'container_ports': container.container_ports
          }]
          changed = True
      elif container.state == "Stopped":
        if domain in webapps:
          for cont in webapps[domain]:
            if cont['name'] == container.name:
              webapps[domain].remove(cont)
              changed = True
      if changed:
        write_conf(gen_conf(webapps))
        restart_nginx()

containers = tutum.Container.list()
for cont in containers:
  container = tutum.Container.fetch(cont.resource_uri.split("/")[4])
  domain = has_virtual_host(container.container_envvars)
  if domain and container.state == "Running":
      if domain in webapps:
        webapps[domain].append({
          'name': container.name,
          'node': container.node,
          'private_ip': container.private_ip,
          'public_dns': container.public_dns,
          'resource_uri': container.resource_uri,
          'container_ports': container.container_ports})
      else:
        webapps[domain] = [{
          'name': container.name,
          'node': container.node,
          'private_ip': container.private_ip,
          'public_dns': container.public_dns,
          'resource_uri': container.resource_uri,
          'container_ports': container.container_ports
        }]
write_conf(gen_conf(webapps))
restart_nginx()

events = tutum.TutumEvents()
events.on_message(process_event)
events.run_forever()
