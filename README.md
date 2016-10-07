# esgf-slcs-client-example

This project provides an example client application for the
[ESGF SLCS Server](https://github.com/cedadev/esgf-slcs-server) using
the [Flask](http://flask.pocoo.org/) library to provide a light-weight web application
and the [OAuthLib extensions](https://requests-oauthlib.readthedocs.io) for the
[Requests library](http://docs.python-requests.org/en/master/) for the OAuth interactions.

**NOTE: The following assumes Python 3.**

To run the example client, you first need to create an OAuth application via the
admin interface on your ESGF SLCS Server. The callback URL should be
`http://localhost:5000/oauth_callback`. Take a note of the generated client ID and
secret.

Open `esgf_slcs_client_example.py` and modify the 'settings' to reflect your setup
(including the client ID and secret from above). Then run:

```
$ pyvenv venv
$ venv/bin/pip install flask requests-oauthlib pyopenssl
$ venv/bin/python esgf_slcs_client_example.py
```
