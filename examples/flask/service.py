import os
from flask import Flask
from microkubes.gateway import KongGatewayRegistrator
from microkubes.security import FlaskSecurity

app = Flask(__name__)
registrator = KongGatewayRegistrator(os.environ.get("API_GATEWAY_URL", "http://localhost:8000"))  # Use the Kong registrator for Microkubes

# set up a security chain
sec = (FlaskSecurity().
        keys_dir("/run/secrets").   # set up a key-store that has at least the public keys from the platform
        jwt().                # Add JWT support
        oauth2().             # Add OAuth2 support
        build())              # Build the security for Flask

# Self-registration on the API Gateway must be the first thing we do when running this service.
# If the registration fails, then the whole service must terminate.
registrator.register(name="hello-service",                  # the service name.
                     paths=["/"],                      # URL pattern that Kong will use to redirect requests to out service
                     host="hello-service.service.consul",   # The hostname of the service.
                     port=5000)                             # Flask default port. When redirecting, Kong will call us on this port.

@app.route("/hello")
@sec.secured   # this action is now secure
def hello():
    auth = sec.context.get_auth()  # get the Auth from the security context
    return "Hello %s from Flask service on Microkubes" % auth.username
