# Python edgegrid module
""" Copyright 2015 Akamai Technologies, Inc. All Rights Reserved.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 
 You may obtain a copy of the License at
    
    http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
import sys, os,logging
if sys.version_info[0] >= 3:
     # python3
     from urllib import parse
else:
     # python2.7
     import urlparse as parse


import requests, logging, json
from random import randint
from akamai.edgegrid import EdgeGridAuth
from Lib.GCS.config import EdgeGridConfig



class EdgeGridHttpCaller():
    def __init__(self, session, debug, verbose, baseurl,log=None):
        self.log = log
        self.debug = debug
        self.verbose = True
        self.session = session
        self.baseurl = baseurl
        
        return None
   
    def urlJoin(self, url, path):
        return parse.urljoin(url, path)
 
    def getResult(self, endpoint, parameters=None, headers=None):
      path = endpoint
      
      if (headers == 'cps'):
        self.session.headers.update({'Accept': 'application/vnd.akamai.cps.enrollments.v9+json'})
      elif (headers == 'cpsH'):
        self.session.headers.update({'Accept': 'application/vnd.akamai.cps.certificate-history.v1+json'})
      endpoint_result = self.session.get(parse.urljoin(self.baseurl,path), params=parameters)

      
      status = endpoint_result.status_code
      try:
        result = endpoint_result.json()
      except:
        result = {'error-detail':endpoint_result.text}
        self.httpErrors(endpoint_result.status_code, path+'?'+parameters,result)
      if 'error-detail' in result:
        return {}
      
      return result
    
    def httpErrors(self, status_code, endpoint, result):

      if not isinstance(result, list):
      	details = result.get('detail') or result.get('details') or ""
      else:
        details = ""
      if status_code == 403:
                    error_msg =  "Call to %s failed with a 403 result" % endpoint
                    # error_msg +=  "ERROR: This indicates a problem with authorization.\n"
                    # error_msg +=  "ERROR: Please ensure that the credentials you created for this script\n"
                    # error_msg +=  "ERROR: have the necessary permissions in the Luna portal.\n"
                    # error_msg +=  "ERROR: Problem details: %s\n" % details
                    self.log.error(error_msg)
      
      if status_code in [400, 401]:
                    error_msg =  "Call to %s failed with a %s result" % (endpoint, status_code)
                    # error_msg +=  "This indicates a problem with authentication or headers.\n"
                    # error_msg +=  "Please ensure that the .edgerc file is formatted correctly.\n"
                    # error_msg +=  "If you still have issues, please use gen_edgerc.py to generate the credentials\n"
                    # error_msg +=  "Problem details: %s\n" % result
                    self.log.error(error_msg)
      
      if status_code in [404]:
                    error_msg =  "Call to %s failed with a %s result" % (endpoint, status_code)
                    # error_msg +=  "ERROR: This means that the page does not exist as requested.\n"
                    # error_msg +=  "ERROR: Please ensure that the URL you're calling is correctly formatted\n"
                    # error_msg +=  "ERROR: or look at other examples to make sure yours matches.\n"
                    # error_msg +=  "ERROR: Problem details: %s\n" % details
                    self.log.error(error_msg)
      
      error_string = None
      if "errorString" in result:
                   if result["errorString"]:
                           error_string = result["errorString"]
      else:
        for key in result:
          if type(key) is not str or isinstance(result, dict) or not isinstance(result[key], dict):
            continue
          if "errorString" in result[key] and type(result[key]["errorString"]) is str:
            error_string = result[key]["errorString"]
      if error_string:
                    self.log.error("Call caused a server fault.")
                    error_msg +=  "Problem details: %s" % error_string
                    self.log.error(error_msg)
    
    def postResult(self, endpoint, body, parameters=None):
        headers = {'content-type': 'application/json'}
        path = endpoint
        
        endpoint_result = self.session.post(parse.urljoin(self.baseurl,path), data=body, headers=headers, params=parameters)
        status = endpoint_result.status_code
        
 
        if status == 204:
           return {}

        return endpoint_result.json()

    def postFiles(self, endpoint, file):
        path = endpoint
        endpoint_result = self.session.post(parse.urljoin(self.baseurl,path), files=file)
        status = endpoint_result.status_code
      
        if status == 204:
           return {}
        self.httpErrors(endpoint_result.status_code, path, endpoint_result.json())
        

        return endpoint_result.json()
    
    def putResult(self, endpoint, body, parameters=None):
        headers = {'content-type': 'application/json'}
        path = endpoint
        
        endpoint_result = self.session.put(parse.urljoin(self.baseurl,path), data=body, headers=headers, params=parameters)
        status = endpoint_result.status_code
 
        if status == 204:
            return {}

        return endpoint_result.json()
    
    def deleteResult(self, endpoint):
        endpoint_result = self.session.delete(parse.urljoin(self.baseurl,endpoint))
        status = endpoint_result.status_code
        if status == 204:
            return {}
        return endpoint_result.json()

 