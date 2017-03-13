"""
This file contains an example web application that interacts with an ESGF SLCS Server.
"""

import subprocess
from pprint import pformat
from time import time
from base64 import b64encode

from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import requests
from requests_oauthlib import OAuth2Session

from OpenSSL import crypto

################################################################################
## SETTINGS - MODIFY TO REFLECT YOUR SETUP
################################################################################

esgf_slcs_server = 'https://www.my-slcs-server.com'
client_id = "<oauth client id>"
client_secret = "<oauth client secret>"

################################################################################
## END SETTINGS
################################################################################

# Uncomment for detailed oauthlib logs
#import logging
#import sys
#log = logging.getLogger('oauthlib')
#log.addHandler(logging.StreamHandler(sys.stdout))
#log.setLevel(logging.DEBUG)

authorize_url = "{}/oauth/authorize".format(esgf_slcs_server)
token_url = "{}/oauth/access_token".format(esgf_slcs_server)
refresh_url = token_url
certificate_url = "{}/oauth/certificate/".format(esgf_slcs_server)
scope = [certificate_url]
redirect_uri = 'http://localhost:5000/oauth_callback'

app = Flask(__name__)

@app.route("/")
def esgf_slcs_client():
    """
    Displays a page of options to the user.
    """
    return """
    <h1>ESGF SLCS Client Example</h1>

    <ul>
        <li><a href="/get_token">Get an OAuth token</a></li>
        <li><a href="/clear_token" rel="nofollow">Clear current OAuth token</a></li>
        <li><a href="/show_token">Show current OAuth token</a></li>
        <li><a href="/get_certificate">Get a user certificate</a></li>
    </ul>
    """


@app.route("/get_token", methods = ['GET'])
def get_token():
    """
    Redirect the user to the ESGF SLCS Server for authorisation.
    """
    # Reset any existing state in the session
    if 'oauth_state' in session:
        del session['oauth_state']
    # Generate a new state and the accompanying URL to use for authorisation
    slcs = OAuth2Session(client_id, redirect_uri = redirect_uri, scope = scope)
    auth_url, state = slcs.authorization_url(authorize_url)
    # state is used to prevent CSRF - keep for later
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route("/oauth_callback", methods = ['GET'])
def oauth_callback():
    """
    Convert an authorisation grant into an access token.
    """
    # If we have not yet entered the OAuth flow, redirect to the start
    if 'oauth_state' not in session:
        return redirect(url_for('get_token'))
    # Notify of any errors
    if 'error' in request.args:
        return """
        <h1>ESGF SLCS Client Example</h1>

        <h2>ERROR: <code>{}</code></h2>

        <p><a href="/">Back to menu</a></p>
        """.format(request.args.get('error'))
    # Exchange the authorisation grant for a token
    slcs = OAuth2Session(client_id,
                         redirect_uri = redirect_uri,
                         state = session.pop('oauth_state'))
    token = slcs.fetch_token(
        token_url,
        client_secret = client_secret,
        authorization_response = request.url,
        # Don't bother verifying certificates as we are likely using a test SLCS
        # server with a self-signed cert...
        verify = False
    )
    # Store the token in the session
    session['oauth_token'] = token
    # Redirect to the token view
    return redirect(url_for('show_token'))


@app.route("/clear_token", methods = ['GET'])
def clear_token():
    """
    Clears the current OAuth token from the session.
    """
    if 'oauth_token' in session:
        del session['oauth_token']
    return redirect('/')


@app.route("/show_token", methods = ['GET'])
def show_token():
    """
    Show the current token.
    """
    if 'oauth_token' in session:
        content = "<pre>{}</pre>".format(pformat(session['oauth_token'], indent=4))
    else:
        content = """
        <p>No OAuth token in session</p>
        """
    return """
    <h1>ESGF SLCS Client Example</h1>

    <h2>Current OAuth Token</h2>

    {}

    <p><a href="/">Back to menu</a></p>
    """.format(content)


@app.route("/get_certificate", methods = ['GET'])
def get_certificate():
    """
    Generates a new private key and certificate request, submits the request to be
    signed by the SLCS CA and prints the resulting key/certificate pair.

    This view demonstrates the automatic refreshing of tokens if they have expired.
    """
    # If there is no token in the session, redirect to the start of the flow
    if 'oauth_token' not in session:
        return """
        <h1>ESGF SLCS Client Example</h1>

        <h2>Get user certificate</h2>

        <p>No OAuth token in session</p>

        <p><a href="/">Back to menu</a></p>
        """
    # Generate a new key pair
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode("utf-8")
    # Generate a certificate request using the key pair
    cert_request = crypto.X509Req()
    cert_request.set_pubkey(key_pair)
    cert_request.sign(key_pair, "md5")
    cert_request = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, cert_request)
    # Build the OAuth session object
    slcs = OAuth2Session(
        client_id,
        token = session['oauth_token'],
        auto_refresh_url = refresh_url,
        auto_refresh_kwargs = {
            'client_id' : client_id,
            'client_secret' : client_secret,
        },
        # Update the token in the session with the new token if it is refreshed
        token_updater = lambda t: session['oauth_token'].update(t)
    )
    response = slcs.post(
        certificate_url,
        data = { 'certificate_request' : b64encode(cert_request) },
        verify = False
    )
    # Convert the certificate into a human readable form using openssl commands
    openssl = subprocess.Popen(
        ['openssl', 'x509', '-text'],
        stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT,
        universal_newlines = True
    )
    stdout, stderr = openssl.communicate(input = response.text)
    if response.status_code == 200:
        # If the response is a 200 OK, it should contain a certificate
        content = "<pre>{}</pre><pre>{}</pre>".format(stdout, private_key)
    else:
        # All other status codes are an error
        content = "<pre>ERROR: {} {}</pre>".format(response.status_code, response.reason)
    return """
    <h1>ESGF SLCS Client Example</h1>

    <h2>Get user certificate</h2>

    {}

    <p><a href="/">Back to menu</a></p>
    """.format(content)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    app.secret_key = os.urandom(24)
    app.run(debug = True)
