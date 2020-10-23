import requests, logging, json, sys
from Lib.GCS.http_calls import EdgeGridHttpCaller
from random import randint
from akamai.edgegrid import EdgeGridAuth
from Lib.GCS.config import EdgeGridConfig
import urllib
import socket
import subprocess
import os
import dns.resolver
import functools

class Wrapper:
	"""
	A simple wrapper for the API calls. Each call maps to a API URL and no tampering of the results is done within the class.
	"""

	def __init__(self,log=None): 
		self.log = log
		self.session = requests.Session()
		self.debug = False
		self.verbose = False
		self.section_name = "all"
		self.account = None

		# If all parameters are set already, use them.  Otherwise
		# use the config
		self.config = EdgeGridConfig({},self.section_name)

		if hasattr(self.config, "debug") and self.config.debug:
		  self.debug = True

		if hasattr(self.config, "verbose") and self.config.verbose:
		  self.verbose = True


		# Set the config options
		self.session.auth = EdgeGridAuth(
		            client_token=self.config.client_token,
		            client_secret=self.config.client_secret,
		            access_token=self.config.access_token
		)

		if hasattr(self.config, 'headers'):
		  self.session.headers.update(self.config.headers)

		self.baseurl = '%s://%s/' % ('https', self.config.host)
		self.httpCaller = EdgeGridHttpCaller(self.session, self.debug,self.verbose, self.baseurl,self.log)

	def getGroups(self):
		"""Return the group and contract details based on PAPI credentials.

			Keyword arguments:
				None

			Return type:
				List of groups
		"""
		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)
		else:	
			params = None

		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)

		return self.httpCaller.getResult('/papi/v1/groups/',parameters=params)
		

	def getContractNames(self):	
		"""
		Returns the contract id and contract name for a given contract Id

			Keyword arguments:
				None

			Return parameter:
				Hash of contractId and contract name. Same as the output from the raw API call to "/papi/v1/groups/"
		"""
		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)
		else:	
			params = None
		return self.httpCaller.getResult('/papi/v1/contracts/',parameters=params)	

	def getProducts(self, contractId):
		"""
		Returns the contract information for the contractId

			Keyword arguments:
				contractId 

			Return parameter:
				Contract details
		"""
		if self.account:
			params = 'accountSwitchKey={0}&contractId={1}'.format(self.account,contractId)
		else:	
			params = 'contractId={0}'.format(contractId)
		return self.httpCaller.getResult('/papi/v1/products/',parameters=params)
		

	def getCPCodes(self, groupId, contractId):
		"""
		Return the CP Code details for a groupId-contractId combination

			Keyword arguments:
				groupId
				contractId
				
			Return parameter:
				List of CP Codes
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/cpcodes/',parameters=params) 
		


	def getEdgeHostNames(self,groupId, contractId,version=None):
		"""
		Returns the edgehostnames by groupId. If all groups for an account are passed to this function, it will return all the Edge host names associated with the account.

			Keyword arguments:
				groupId
				contractId

			Return parameter:
				List of edge hostnames
		"""		
		if version == 'hapi':
			endpoint = '/hapi/v1/edge-hostnames'
			if self.account:
				params = 'accountSwitchKey={0}'.format(self.account)	
		else:
			endpoint = '/papi/v1/edgehostnames/'
			if self.account:
				params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
			else:	
				params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult(endpoint,parameters=params) 	

	def getAppSecConfigurations(self):
		"""
			Keyword arguments:
				None

			Return parameter:
				Lists available versions for the specified security configuration
				https://developer.akamai.com/api/cloud_security/application_security/v1.html#getconfigurations
		"""
		endpoint = '/appsec/v1/configs'
		params = None
		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)

		return self.httpCaller.getResult(endpoint,parameters=params) 			
	def getAppSecMatchTargets(self,configID,version):

		endpoint = '/appsec/v1/configs/{0}/versions/{1}/match-targets'.format(configID,version)
		params = None
		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)
	
		return self.httpCaller.getResult(endpoint,parameters=params) 			

	def getProperties(self, groupId, contractId):
		"""
		Returns the names of properties associated with a group. If all groups for an account are passed to this function, it will return all the properties associated with the account.

			Keyword arguments:
				groupId
				contractId

			Return parameter:
				List of properties
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		
		return self.httpCaller.getResult('/papi/v1/properties/',parameters=params)		

	def getPropertyVersions(self, propertyId, groupId, contractId):
		"""
		Returns the property versions. This can be used to find the audit trail details for a configuration

			Keyword arguments:
				propertId
				groupId
				contractId

			Return parameters:
				List of property versions
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/{0}/versions/'.format(propertyId),parameters=params)			

	def getavailableBehavior(self, propertyId,propertyVersion, contractId, groupId ):
		"""
		Returns a lists of set of behaviors you may apply within a property version’s rules. The available set is determined by the product under which you created the property, 
		and any additional modules enabled under your account.
			Keyword arguments:
				propertId
				propertyVersion
				contractId
				groupId

			Return parameters:
				List of behaviors for 
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/{0}/versions/{1}/available-behaviors'.format(propertyId,propertyVersion),parameters=params)		

	def getVersionDetails(self, propertyId, groupId, contractId, propertyVersion=1):
		"""
		Returns information about a specific property version

			Keyword arguments:
				propertyVersion: Default version is 1, the first version.
				propertId
				groupId
				contractId

			Return parameters:
				Details on a specific property version
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/{0}/versions/{1}'.format(propertyId,propertyVersion),parameters=params)		

	def getLatestVersionDetails(self, propertyId, groupId, contractId):
		"""
		Returns information about a specific property version

			Keyword arguments:
				propertyVersion: Default version is 1, the first version.
				propertId
				groupId
				contractId

			Return parameters:
				Details on a specific property version
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/latest/versions/{0}'.format(propertyId),parameters=params)			

	def getConfigRuleTree(self, propertyId, versionNumber, groupId, contractId):
		"""
		Returns all the Property Manager rule details. It will not retrieve advanced code.

			Keyword arguments:
				propertyId
				versionNumber - Specific version for which we need the rules
				groupId
				contractId

			Return parameters:
				Configuration tree rule for a given configuration
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/{0}/versions/{1}/rules/'.format(propertyId,versionNumber),parameters=params)	


	def getPropertyHostNames(self, propertyId, versionNumber, groupId, contractId):
		"""
		Returns the host names associated with a configuration.

			Keyword arguments:
				propertyId
				versionNumber - Specific version for which we need the rules
				groupId
				contractId

			Return parameters:
				List of host names belonging to the configuration			
		"""
		if self.account:
			params = 'accountSwitchKey={0}&groupId={1}&contractId={2}'.format(self.account,groupId,contractId)
		else:	
			params = 'groupId={0}&contractId={1}'.format(groupId,contractId)
		return self.httpCaller.getResult('/papi/v1/properties/{0}/versions/{1}/hostnames/'.format(propertyId,versionNumber),parameters=params)	

	def getEnrollmentHistory(self,enrollementID):
		if self.account:
			params = 'accountSwitchKey={0}'.format(self.account)
		
		
		return self.httpCaller.getResult('/cps/v2/enrollments/{0}/history/certificates'.format(enrollementID),parameters=params, headers='cpsH')
	def getEnrollements(self, contractId):
		"""
		Returns the enrollements associated with a contractId.

			Keyword arguments:
				contractId
				
			Return parameters:
				List of enrollments associated with a contractId			
		"""
		
		if self.account:
			params = 'accountSwitchKey={0}&contractId={1}'.format(self.account,contractId)
		else:	
			params = 'contractId={0}'.format(contractId)
		
		return self.httpCaller.getResult('/cps/v2/enrollments',parameters=params, headers='cps')	

	@functools.lru_cache()
	def getCNAME(self, hostname):
		"""
		Runs a dig command to find the CNAME for a given host name.
		If a CNAME is found, it returns it. Else returns a None.

			Keyword arguments:
				hostname: The host name for which we need the CNAME
		"""
		try:
			return (dns.resolver.query(hostname, 'CNAME')).response.answer[0][0]
		except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
			return None

	@functools.lru_cache()
	def getEsslCname(self,hostname):
		tlds = ["akamaiedge", "edgekey"]
		result = None
		try:

			for a in dns.resolver.query(hostname, 'CNAME'):
				if any(tlds in str(a) for tlds in tlds):
					result = a
					break
				else:
					result = self.getCNAMEv2(str(a))
	
		except BaseException as e:
			result = None
		if result is not None:
			return str(result)
		
		return results
	@functools.lru_cache()
	def checkIfCDN(self,dnsRecord):
		result = False
		tlds = ["akamai", "edgesuite", "edgekey", "edgestreams","ec9","d4p"]
		try:
			
			for a in dns.resolver.query(dnsRecord, 'CNAME'):
				if any(tlds in str(a) for tlds in tlds):
					result = True
					break
				else:
					result = self.checkIfCDN(str(a))
		# TODO: Be more specific
		except BaseException as e:
			# print(str(e))
			result = "Unknown"

		return result
	@functools.lru_cache()
	def checkSlot(self,dnsRecord):
		result = None
		tlds = ["akamaiedge"]
		try:
			for a in dns.resolver.query(dnsRecord, 'CNAME'):
				if any(tlds in str(a) for tlds in tlds):
					result = int(str(a).split('.')[0][1:])
					break
				else:
					result = self.checkSlot(str(a))
		# TODO: Be more specific
		except BaseException as e:
			return result
		return result
	@functools.lru_cache()
	def checkIfCdnIP(self, ipaddress):
		"""
		Returns if an IP address blongs to Akamai or if it is not an Akamai IP. It uses the OS command "host" on systems
		that supports it. Else, it uses the command nslookup.

			Keyword arguments:
				ipaddress

			Return parameters:
				A boolean flag based on whether the call returns a true or a false.
		"""
		result = False
		

		try:
			if os.name =="nt":
				resp = str ( subprocess.check_output(['nslookup',ipaddress]) )
				print(resp)
				if resp.find('akamai'):
					result=True
			else:
				resp = str( subprocess.check_output(['host', ipaddress]) )
				print (resp)
				resp = resp.split(' ')
				if len(resp) >=5:
					if resp[4].find('akamai') > -1:
						result=True
		except subprocess.CalledProcessError:
			pass		
		return result
	@functools.lru_cache()
	def getIpAddress(self, hostname):
		result = "0.0.0.0"
		try:
			result =  socket.gethostbyname(hostname)
		except Exception:
			pass
		return result
	def reporting(self,cpcodes,startDate,endDate, reportType):
		if self.account:
			params = 'accountSwitchKey='+self.account+'&start='+startDate+'T00:00:00Z&end='+endDate+'T00:00:00Z&interval=DAY&objectIds='+str(cpcodes)+'&metrics=allEdgeHits,allHitsOffload'.format(self.account,startDate,endDate,cpcodes)
		else:	
			params = 'start={1}T00%3A00%3A00Z&end={2}T00%3A00%3A00Z&interval=DAY&objectIds={2}&metrics=allEdgeHits,allHitsOffload'.format(startDate,endDate,cpcodes)
		return self.httpCaller.getResult('/reporting-api/v1/reports/urlhits-by-url/versions/1/report-data',params)
	def getProducts(self,contractID):
		if self.account:
			params = 'accountSwitchKey={0}&contractId={1}'.format(self.account,contractID)
		else:	
			params = 'contractId={1}'.format(contractID)
		return self.httpCaller.getResult('/papi/v1/products',params)

	def clear_cache(self):
		self.getIpAddress.cache_clear()
		self.getCNAME.cache_clear()
		self.checkIfCDN.cache_clear()
		self.getEsslCname.cache_clear()
		self.checkSlot.cache_clear()
		self.checkIfCdnIP.cache_clear()

		 
		 
		 
		 
		

if __name__=="__main__":
	w = Wrapper()
