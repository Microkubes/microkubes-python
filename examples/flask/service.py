import os
import logging
from flask import Flask
from microkubes.gateway import KongGatewayRegistrator
from microkubes.security import FlaskSecurity

from itsdangerous import base64_decode
import zlib

import requests

import os

from flask import (Flask, request, render_template, redirect, session, make_response)

from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
# registrator = KongGatewayRegistrator(os.environ.get("API_GATEWAY_URL", "http://localhost:8000"))  # Use the Kong registrator for Microkubes

# set up a security chain
sec = (FlaskSecurity().
        keys_dir("./keys").   # set up a key-store that has at least the public keys from the platform
        saml(registration_url='http://localhost:8080/saml/idp/services').                # Set SAML SP
        build())              # Build the security for Flask

# Self-registration on the API Gateway must be the first thing we do when running this service.
# If the registration fails, then the whole service must terminate.
# registrator.register(name="hello-service",                  # the service name.
#                      paths=["/hello"],                      # URL pattern that Kong will use to redirect requests to out service
#                      host="hello-service.service.consul",   # The hostname of the service.
#                      port=5000)                             # Flask default port. When redirecting, Kong will call us on this port.

@app.route("/")
@sec.secured   # this action is now secure
def hello():
    auth = sec.context.get_auth()  # get the Auth from the security context
    return "Hello %s from Flask service on Microkubes" % auth.username

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'flask/saml'))
    return auth

def prepare_flask_request(req):
    """Prepare SAML request
    """
    url_data = urlparse(req.url)

    return {
        'https': 'on' if req.scheme == 'https' else 'off',
        'http_host': req.host,
        'server_port': url_data.port,
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy(),
    }

# @app.route('/metadata')
# def metadata():
#     req = prepare_flask_request(request)
#     auth = init_saml_auth(None)
#     settings = auth.get_settings()
#     metadata = settings.get_sp_metadata()
#     errors = settings.validate_metadata(metadata)

#     headers = {'Content-Type': 'application/xml'}
#     requests.post('http://localhost:8080/saml/idp/services', data=metadata, headers=headers)


#     if len(errors) == 0:
#         resp = make_response(metadata, 200)
#         resp.headers['Content-Type'] = 'text/xml'
#     else:
#         resp = make_response(', '.join(errors), 500)

#     return resp

@app.route('/acs', methods=['GET', 'POST'])
def acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()

    if len(errors) == 0:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlSessionIndex'] = auth.get_session_index()
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            return redirect(auth.redirect_to(request.form['RelayState']))



