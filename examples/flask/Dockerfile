FROM python:3.7-slim-stretch

RUN apt-get update && apt-get install -y git

# Install microkubes-python
RUN pip install "git+https://github.com/Microkubes/microkubes-python#egg=microkubes-python"

# Install flask
RUN pip install Flask

# Add the service file to the container image
ADD service.py /service.py

# Set up flask app, a file that creates instance of Flask app
ENV FLASK_APP=/service.py

# run the service
CMD ["flask", "run", "--host=0.0.0.0"]