Microkubes Python library
=========================

Python tools and helpers for microservices written in Python on top of Microkubes.

# Installation and setup

To install micrkubes-python run:

```bash

pip install "git+https://github.com/Microkubes/microkubes-python#egg=microkubes-python"

```

If you want to hack around, you can install it with ```pip```:

```
pip install -e "git+https://github.com/Microkubes/microkubes-python#egg=microkubes-python"
```

or clone this repository directly:

```

git clone https://github.com/Microkubes/microkubes-python
cd microkubes-python
pip setup.py develop
pip install -r dev-requirements.txt

```

# Use it with Flask

If you're developing with [Flask](http://flask.pocoo.org/), then you need to install it additionaly:

```bash
pip install Flask
```


## Example service in Flask

As an example we can write small hello-world-like service in Flask (service.py):

```python
import os
from flask import Flask
from microkubes.gateway import KongGatewayRegistrator


app = Flask(__name__)
registrator = KongGatewayRegistrator(os.environ.get("API_GATEWAY_URL", "http://localhost:8001"))  # Use the Kong registrator for Microkubes


# Self-registration on the API Gateway must be the first thing we do when running this service.
# If the registration fails, then the whole service must terminate.
registrator.register(name="hello-service",                  # the service name.
                     paths=["/hello"],                      # URL pattern that Kong will use to redirect requests to out service
                     host="hello-service.services.consul",  # The hostname of the service.
                     port=5000)                             # Flask default port. When redirecting, Kong will call us on this port.


@app.route("/hello")
def hello():
    return "Hello from Flask service on Microkubes"

```


# Gateway registration



# Security