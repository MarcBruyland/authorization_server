import json
import requests
#import ssl

from flask import (Flask, make_response, render_template, redirect, request,
                   url_for)

AUTH_PATH = 'http://localhost:5001/auth'
TOKEN_PATH = 'http://localhost:5001/token'
RES_PATH = 'http://localhost:5002/users'
REDIRECT_URL = 'http://localhost:5000/callback'

CLIENT_ID = 'sample-client-id'
CLIENT_SECRET = 'sample-client-secret'

app = Flask(__name__)


@app.before_request
def before_request():
  # Redirects user to the login page if access token is not present
  print(f"***before_request - request.endpoint: {request.endpoint}")
  if request.endpoint not in ['login', 'callback']:
    access_token = request.cookies.get('access_token')
    print(f"***before_request - access_token: {access_token}")
    if access_token:
      pass
    else:
      print(f"before_request: redirect to url_for('login'): {url_for('login')}")
      return redirect(url_for('login'))


@app.route('/')
def main():
  # Retrieves a list of users
  print("route /")
  access_token = request.cookies.get('access_token')
  print(f"***main - access_token: {access_token}")
  print(f"***main - get: {RES_PATH}")
  r = requests.get(RES_PATH, headers={
    'Authorization': 'Bearer {}'.format(access_token)
  })
  print(f"***main - r.status_code: {r.status_code}")

  if r.status_code != 200:
    return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500

  users = json.loads(r.text).get('results')
  print(f"***main - users: {users}")
  print(f"***main – render template users.html")
  return render_template('users.html', users=users)


@app.route('/login')
def login():
  # Presents the login page
  print("route /login")
  print("***login - render template AC_login.html")
  return render_template('AC_login.html',
                         dest=AUTH_PATH,
                         client_id=CLIENT_ID,
                         redirect_url=REDIRECT_URL)


@app.route('/callback')
def callback():
  # Accepts the authorization code and exchanges it for access token
  print("route /callback")
  authorization_code = request.args.get('authorization_code')
  print(f"***callback - authorization_code: {authorization_code}")

  if not authorization_code:
    return json.dumps({
      'error': 'No authorization code is received.'
    }), 500

  print(f"***callback - post: {TOKEN_PATH}")
  r = requests.post(TOKEN_PATH, data={
    "grant_type": "authorization_code",
    "authorization_code": authorization_code,
    "client_id" : CLIENT_ID,
    "client_secret" : CLIENT_SECRET,
    "redirect_url": REDIRECT_URL
  })
  print(f"***callback - r.status_code: {r.status_code}")
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
  
  access_token = json.loads(r.text).get('access_token')
  print(f"***callback - access_token: {access_token}")
  print(f"***callback - redirect(url_for('main')): {url_for('main')}")
  response = make_response(redirect(url_for('main')))
  response.set_cookie('access_token', access_token)
  print(f"***callback (end)- response: {response}")
  return response


if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port=5000, debug=True)