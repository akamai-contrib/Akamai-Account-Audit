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

import sys, os

if sys.version_info[0] >= 3:
     # python3
     from configparser import ConfigParser
     import http.client as http_client
else:
     # python2.7
     from ConfigParser import ConfigParser
     import httplib as http_client

import argparse
import logging

class EdgeGridConfig():

    def __init__(self, config_values, configuration, flags=None):        
        config = ConfigParser()
    
        config.readfp(open(  os.path.expanduser("~/.edgerc") ) )
        arguments = {}
    
        for key, value in config.items(configuration):
            arguments[key] = value        


        for option in arguments:
            setattr(self,option,arguments[option])

        self.create_base_url()        
    


    def create_base_url(self):
        self.base_url = "https://%s" % self.host

        

