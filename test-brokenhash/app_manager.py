import subprocess
import os,platform
import json
import time
import requests
import base64
from common import baseUrl, hostname

class App:
    tc_count=0
    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.open_application()
        self.req = requests.Session()

    def open_application(self):
        """
                Function to Open the application.
         """
        return os.startfile(os.getcwd()+"/broken-hashserve/broken-hashserve_win.exe")
    def get_hash(self,job_id):
        """
        Function to submit GET request to hash endpoint.
        Arguments:
            job_id (str): Job ID that links POST request to encoded password hash.
        Return Values:
                response (obj): Response object from GET request
            """
        time.sleep(3)
        endpoint = '/hash'
        response = requests.get(baseUrl + endpoint + '/' + job_id)
        return response

    def post_hash(self,password):
        """
        Function to submit POST request to hash endpoint.
        Arguments:
            password (str): Password to be hashed and ecoded.
        Return Values:
            res (obj): Response object from POST request
        """
        endpoint = '/hash'
        data = {'password': password  }
        response = requests.post(baseUrl+endpoint, json=data)
        return response

    def get_stats(self):
        """
        Function to submit GET request to stats endpoint.
        Arguments:
        Return Values:
            res (obj): Response object from GET request
         """
        """
         Function to submit GET request to stats endpoint.

         Args:

         Returns:
             res (obj): Response object from GET request
         """
        endpoint = '/stats'
        response = requests.get(baseUrl + endpoint)

        return response

    def get_stats_statuscode(self):
        """
        Function to submit GET request to stats endpoint.
        Arguments:
        Return Values:
            res.status_code : Response status code for GET request
        """
        endpoint = '/stats'
        response = requests.get(baseUrl + endpoint)
        return response.status_code

    def get_stats_response_text(self):
        """
        Function to submit GET request to stats endpoint.
        Arguments:
        Return Values:
            response : Response status code for GET request
        """
        endpoint = '/stats'
        res = requests.get(baseUrl + endpoint)
        return res.text



    def pingHost(self):
        """Returns True if host (str) responds to a ping request."""
        retry_packets=2
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # Building the command. Ex: "ping -c 1 google.com"
        command = ['ping', param, str(retry_packets), hostname]
        return subprocess.call(command) == 0



    def create_hash_id(self,pswd):
        data = {'password':pswd}
        headers = {'Accept':'application/json'}
        endPoint = "/hash"
        response = requests.post(baseUrl+endPoint, json=data, headers=headers)
        print("Hash ID is : "+response.text)
        print("Response Code :"+str(response.status_code))
        return response

    def get_stats(self):
        endpoint="/stats"
        response = requests.get(baseUrl + endpoint)
        response_body = json.loads(response.text)
        print(response.text)
        print(response.status_code)
        print(response_body)
        assert response_body['TotalRequests'] >= 0
        assert response_body['AverageTime'] >= 0
        assert response.status_code == 200

    def isBase64(self, s):
        try:
            return base64.b64encode(base64.b64decode(s)) == s
        except Exception:
            return False


    def shutdown(self):
        url = baseUrl + '/hash'
        data = 'shutdown'
        response = requests.post(url, data=data)
        print("\nApplication is shutting down")
        return response

    def is_json(self,res):
        try:
            json.loads(res)
        except ValueError:
            return False
        return True

    def is_key(self,res, key):
        """
        Function to validate key in JSON for response object

        Args:
            res (obj): Response object from a request.
            key (str): Key to check for in response

        Returns:
                bool: Returns True if key exists, else returns False.
        """
        if self.is_json(res):
            json_contents = json.loads(res)
            if key in json_contents:
                return True
            else:
                return False
        else:
            return False