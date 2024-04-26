import msal
from msal import PublicClientApplication
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import LegacyApplicationClient
import webbrowser
import os
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
import time
import requests
import base64

class credentials():
    def __init__(self, serverURL, clientId, header):
        self.serviceName: str = serviceName
        #string for the serverURL
        self.serverURL: str = serverURL
        #list for scopes, if needed
        self.scopes: list(str) = scopes
        #string for clientId
        self.clientId: str = clientId
        self.clientSecret: str = clientSecret
        self.tenantId: str = tenantId

class canvas(credentials):
    def __init__(self):
        self.serverURL: str = "https://canvas.instructure.com"
        #AKA Account ID
        self.tenantId: str = "YOUR_TENANT_ID"
        self.accessToken: str = "YOUR_ACCESS_TOKEN"
        self.header: dict = {'Authorization': 'Bearer ' + self.accessToken,'Content-Type': 'application/json'}

class mediasite(credentials):
    def __init__(self):
        self.serverURL:str = "https://{0}/mediasite6/api/v1".format("YOUR MEDIASITE SERVER")
        self.accessToken = "YOUR_ACCESS_TOKEN"
        self.header = {'sfapikey': self.accessToken,'Content-Type': 'application/json','Authorization': 'Basic {0}'.format("YOUR AUTH KEY")}

class outlook(credentials):
    def makeAuthToken(self,clientId,authorizationURL,scopes):
        clientInstance = msal.PublicClientApplication(client_id = clientId, authority= authorizationURL)
        flow = clientInstance.acquire_token_interactive(scopes=scopes)
        return(flow['access_token'])
    def __init__(self):
        self.serverURL: str = "https://graph.microsoft.com/v1.0"
        self.clientId: str = "YOUR_CLIENT_ID"
        self.tenantId: str = "YOUR_TENANT_ID"
        self.authorizationURL: str = "https://login.microsoft.com/{0}".format(self.tenantId)
        self.scopes:list(str)= ["https://graph.microsoft.com/.default"]
        self.accessToken: str = self.makeAuthToken(self.clientId,self.authorizationURL,self.scopes)
        self.header:dict = {"Authorization": "Bearer " + self.accessToken, "Prefer": "outlook.body-content-type = 'text'"}
        self.extensions: dict ={"getArchive":"/users/{0}/mailFolders/{1}/".format("YOUR_USER", "YOUR_FOLDER")}
        self.parameters: dict ={"filtedByClientID":"/messages?filter=conversationID eq '{0}'",
                                "topMessages":"/messages?top={0}"}

class ems(credentials):
    def makeAuthToken(self, serverURL, clientId, clientSecret):
        payload = {"clientId": clientId, "secret":clientSecret}
        endpoint = serverURL + "/clientauthentication"
        tempHeader:dict = {"Content-Type":"application/json"}
        resp = requests.post(endpoint,headers=tempHeader, json=payload)
        return(resp.json()['clientToken']) 
    def __init__(self):
        self.serverURL = "https://{0}.emscloudservice.com/platform/api/v1".format("YOUR_SERVER")
        self.clientId = "YOUR_CLIENT_ID"
        self.clientSecret = "YOUR_CLIENT_SECRET"
        self.accessToken = self.makeAuthToken(self.serverURL, self.clientId, self.clientSecret)
        self.header = {"Content-Type":"application/json", "x-ems-api-token":self.accessToken}
    
class zoom(credentials):
    def makeBase64(self,clientId,clientSecret):
        combinedString = clientId+":"+clientSecret
        combinedStringToBytes = combinedString.encode("ascii")
        base64Bytes= base64.b64encode(combinedStringToBytes)
        return(base64Bytes.decode("ascii"))
    def makeAuthToken(self,authURL,basicAuth):
        tempHeader:dict ={"Authorization": basicAuth}
        resp = requests.post(authURL,headers=tempHeader)
        return(resp.json()['access_token'])
    def __init__(self):
        self.serverURL:str ="https://api.zoom.us/v2"
        self.clientId:str = "YOUR_CLIENT_ID"
        self.clientSecret:str = "YOUR_CLIENT_SECRET"
        #AKA accountId
        self.tenantId:str = "YOUR_TENANT_ID"
        self.authURL:str = "https://zoom.us/oauth/token?grant_type=account_credentials&account_id={0}".format(self.tenantId)
        self.basicAuth:str ="Basic " +  self.makeBase64(self.clientId, self.clientSecret)
        self.accessToken:str = self.makeAuthToken(self.authURL,self.basicAuth)
        self.header:dict = {"Authorization":"Bearer "+self.accessToken}

class panopto(credentials):
    def makeAuthToken(self,serverURL, clientId, clientSecret,scopes):
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        redirectURL = 'http://localhost:9127/redirect'
        redirectPort = 9127
        authorizationEndpoint = '{0}/Panopto/oauth2/connect/authorize'.format(serverURL)
        accessTokenEndpoint = '{0}/Panopto/oauth2/connect/token'.format(serverURL)
        session = OAuth2Session(clientId, scope = scopes, redirect_uri = redirectURL)
        authorization_url, state = session.authorization_url(authorizationEndpoint)
        webbrowser.open_new_tab(authorization_url)
        redirected_path = ''
        with RedirectTCPServer() as httpd:
            print('HTTP server started at port {0}. Waiting for redirect.'.format(redirectPort))
            # Serve one request.
            httpd.handle_request()
            # The property may not be readable immediately. Wait until it becomes valid.
            while httpd.last_get_path is None:
                time.sleep(1)
            redirected_path = httpd.last_get_path
        session.fetch_token(accessTokenEndpoint, client_secret = clientSecret, authorization_response = redirected_path, verify=False)
        return session.token['access_token']
    
    def __init__(self):
        self.serverURL: str = "YOUR_SERVER_URL"
        self.clientId: str = "YOUR_CLIENT_ID"
        self.clientSecret: str = "YOUR_CLIENT_SECRET"
        self.scopes = ("api","openid","offline_access")
        self.accessToken: str = self.makeAuthToken(self.serverURL, self.clientId, self.clientSecret,self.scopes)
        self.header: dict = {'Authorization':"Bearer "+ self.accessToken,'Content-Type': 'application/json'}




class RedirectTCPServer(ThreadingTCPServer):
    def __init__(self):
        # Class property, representing the path of the most recent GET call.
        self.last_get_path = None
        # Create an instance at REDIRECT_PORT with RedirectHandler class.
        super().__init__(('', 9127), RedirectHandler)
        # Override the attribute of the server.
        self.allow_reuse_address = True


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        '''
        Handle a GET request. Set the path to the server's property.
        '''
        self.server.last_get_path = self.path
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body><p>Authorization redirect was received. You may close this page.</p></body></html>'.encode('utf-8'))
        self.wfile.flush()