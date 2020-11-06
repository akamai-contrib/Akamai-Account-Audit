
import argparse, time,re, os,csv,functools, signal,sys, json
import logging,datetime, threading,concurrent.futures
from logging import handlers
from time import gmtime, strftime
from urllib.parse import urlparse
from os.path import splitext
import pandas as pd
import numpy as np
# Local Imports
from Lib.GCS.wrapper import Wrapper
from Lib.GCS.origin_settings import Origin_Settings 
from Lib.GCS.log import ConsoleLogging

def ArgsParser():
	
	parser = argparse.ArgumentParser(description='',formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('--switchKey', type=str, help='Account_ID to Query for multi account management (switch key)',
		required=False)
	parser.add_argument('--verbose', action='store_true', help='Turn on Verbose Mode.')
	parser.add_argument('--section',  type=str, help='EdgeRc section to be used.', 
		required=False,default='papi')  
	parser.add_argument('--type', type=str.lower, choices=['as','os','har'], help='Type of report to be done [account-summary,offload,http-archive]]',
        required=False,default='as')
	parser.add_argument('--cpcodes', nargs='+', type=int, help='List of cpcodes to query. Used only in Offload Analysis.',
        required=False)
	parser.add_argument('--start', type=str, help='Report Start date in format YYYY-MM-DD", if not provided default is start of last month. Used only in Offload Analysis.',
		required=False)
	parser.add_argument('--end', type=str, help='Report Start date in format YYYY-MM-DD", if not provided default is start of last month. Used only in Offload Analysis.',
		required=False)
	parser.add_argument('--domain', type=str, help='Main Domain to be reviewed in HAR, usually it will be the same as the page view URL. Used only in Har Analysis.', 
		required=False)
	parser.add_argument('--first-parties', nargs='+', type=str, help='List of first party domains --domain will be appended to this list. If only one domain is in quesion, --domain is all you need. Used only in Har Analysis.', 
		required=False)
	parser.add_argument('--file', type=str, help='File location to be analysed. Used only in Har Analysis.',
		required=False)
	parser.add_argument('--groupby', type=str.lower, choices=['ext','url'], help='Used only in Offload Analysis. ',
        required=False,default='ext')

	args = vars(parser.parse_args())
	return parser, args

class Aggregator:
   	
	def __init__(self,console,args,section_name):
		
		
		self.args = None
		self.parser	= None
		self.maxThreads = 5
		self.outputdir = "None"
		self.verbose = args['verbose']
		self.log = console.log
		self.wrapper = Wrapper(self.log,section_name)
		self.accountId = None
		self.wrapper.account = None

		self.dfs = {}
		self.startDate = None
		self.endDate = None
		self.accountName = None

		self.productMap = None
		self.reportType = "as"
		self.groupby = args['groupby']

		signal.signal(signal.SIGINT, self.signal_handler)

	def signal_handler(self,sig, frame):
		self.clear_cache()
		self.log.critical("Forced Exit... Bye!..")
		sys.exit(0)	
	
	def _validateDate(self, date):
		"""Returns False if input date does not follow YYYY-MM-DD.

			Keyword arguments:
				date

			Return type:
				Boolean
		"""
		try:
			datetime.datetime.strptime(str(date), '%Y-%m-%d')
			return True
		except ValueError:
			return False
			# raise ValueError("Incorrect data format, should be YYYY-MM-DD")

	def createFolder(self,directoryName):
		"""Creates directores to store outputs, takes the directory name. This value most of the time will be the 
			account Name.

			Keyword arguments:
				directoryName

			Return type:
				None
		"""
		self.outputdir = 'Reports'
		# Create Audit Folder
		try:
			os.stat(self.outputdir)
		except:
			os.mkdir(self.outputdir)

		self.outputdir = self.outputdir+'/'+directoryName.replace(' ','_')+'/'
		# Create Account Folder under Audit
		try:
			os.stat(self.outputdir)
		except:
			os.mkdir(self.outputdir)
		self.outputdir =  self.outputdir + str(datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')).replace(' ','_').replace(':','.') + '-'

	def _getProducts(self, contractId):
		"""
			Return the set of products within a contract as a comma seperated list
			
			Keyword arguments:
					contractId

			Return type:
				list
		"""

		products = self.wrapper.getProducts(contractId)		
		productNames = []
		if 'products' in products:
			for product in products['products']['items']:
				productNames.append(product['productName'])
				new_row = {
					'Product_ID':product['productId'],
					'Product_Name':product['productName']
					}

		if len(productNames) > 1:
			return ",".join(productNames)
		else:
			return []

	def getAccountDetails(self):
		"""
			Gets Account Name from ID, also saves the groups for later functions.	
			Keyword arguments:
					None

			Return type:
				Boolean, but also stores dataframe in self.dfs
		"""

		
		
		if args['switchKey']:
			self.accountId = args['switchKey']
			self.wrapper.account = args['switchKey']
		
		self.groups = self.wrapper.getGroups()

		if 'incidentId' in self.groups:
			self.log.error('Account Not Found or insufficient privileges to complete the operation. Try "--section sectionName" o change edgerc section')
			return False
		if not args['switchKey']:
			self.accountId = self.groups['accountId'][4:]
			# self.wrapper.account = self.groups['accountId'][4:]	
		self.log.info("Account ID: {0}".format(self.accountId))
		self.accountName = self.groups['accountName']
		self.log.info("Account Name: {0}".format(self.accountName))
		csv_file_path = self.createFolder(self.groups['accountName'])
		columns = ["Account_Id", "Account_Name"]
		df_acc= pd.DataFrame(columns=columns)
		new_row = {
		 'Account_Id':self.groups['accountId'][4:],
		 'Account_Name':self.groups['accountName']
		}
		df_acc=df_acc.append(new_row, ignore_index=True)
		
		self.dfs['account'] = df_acc
		self._readProductMap()
		
		return True

	def accountSummary(self):
		"""
			Main function for AS report type, orchestrates function execution.

			Keyword arguments:
					None

			Return type:
				None
		"""
		self.log.info("Creating Contract summary table")
		self.printContracts()
		self.log.info("Creating Groups summary table")
		self.printGroups()
		self.log.info("Creating CP_Code summary table")
		self.printCPcodes()
		self.log.info("Creating edge host name summary table")
		self.printEdgeHostNames()
		self.log.info("Creating Application Security tables")
		self.printAppSec()
		if args['verbose']:
			self.log.info("Creating Property summary. (It may take a while) ")
		else:
			self.log.info("Creating Property summary. (It may take a while, view more with '--verbose') ")
		self.printPropertiesDetails()
		self.log.info("Creating Certificate Table.")
		self.getEnrollments()	
		self.log.info("Creating Summary by Hostname")
		self.presentation()	
		self.log.info("Writing Files...")
		self._writeFiles()

		self.log.info("Report successfull, output can be found here:'Reports/{0}/'".format(self.accountName))

	def printContracts(self):
		"""
			Gets Contracts within Account
			
			Keyword arguments:
					None

			Return type:
				None, but stores dataframe in self.dfs
		"""
		self.log.info("Creating Contracts table.")
		columns = ["Contract_ID" , "Contract_Name", "Products"]
		df_ctr= pd.DataFrame(columns=columns)
		contracts = self.wrapper.getContractNames()	
		for contract in contracts['contracts']['items']:
			products = self._getProducts(contract['contractId'])
			
			new_row = {
				'Contract_ID': contract['contractId'][4:],
				'Contract_Name':contract['contractTypeName'],
				'Products':products
			}
			df_ctr=df_ctr.append(new_row, ignore_index=True)
		self.dfs['contracts'] = df_ctr

	def printGroups(self):	
		"""
			Gets Groups in account

			Keyword arguments:
					None

			Return type:
				None, but stores dataframe in self.dfs
		"""
		self.log.info("Creating Groups table.")
		columns = ["Group_ID", "Group_Name","Parent"]
		df_grp = pd.DataFrame(columns=columns)
		for group in self.groups['groups']['items']:
			grp_id = int(group['groupId'][4:])
			grp_name = group['groupName']
			grp_parent = None
			if 'parentGroupId' in group:
				grp_parent = int(group['parentGroupId'][4:])
			
			new_row = {
				'Group_ID': grp_id,
				'Group_Name':grp_name,
				'Parent':grp_parent
			}
			
			df_grp=df_grp.append(new_row, ignore_index=True)
		self.dfs['groups'] = df_grp

	def printEdgeHostNames(self):
		"""
			Gets EdgeHostnames in account

			Keyword arguments:
					None

			Return type:
				None, but stores dataframe in self.dfs
		"""
		lst_eh = []
		columns = ["Group_ID", "Contract_ID", "Edge_Host_ID", "Edge_Host_Name", "Edge_Host_Domain_Suffix", "Secure", "IPVersion","Product_ID","Map","Slot"]
		df_eh = pd.DataFrame(columns=columns)
		contracts = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=self.maxThreads) as executor:
			for group in self.groups['groups']['items']:
				groupId = group['groupId']
				executor.submit(self.GroupsWorker,'edgehost',group,lst_eh,contracts)
		df_eh= df_eh.append(lst_eh, ignore_index=True)
		
		self.dfs['edgehostnames'] = df_eh	
							
	def PropertyWorker(self,list_grp_configs,list_grp_behaviors,config_details):
		"""
			Gets Property details, 

			Keyword arguments:
					list_grp_configs
					list_grp_behaviors
					config_details

			Return type:
				None, but stores dataframe in self.dfs
		"""
		args = None
		args = ['Prod_Version','Staging_Version', 'Latest_Version']
		if 'propertyName' in config_details:
			self.log.debug("Importing data for property: '{0}'".format(config_details['propertyName']))

			# Assign values to variables here for readability and will be used in rest of function.  
			groupId = config_details['groupId']
			contractId = config_details['contractId']
			propertyId = config_details['propertyId']
			productionVersion = config_details['productionVersion']
			stgVersion = config_details['stagingVersion']
			latestVersion = config_details['latestVersion']
			productId = None
			new_row = {
				'Config_Name': config_details['propertyName'],
				'Group_ID': int(groupId[4:]), 
				'Contract_ID': contractId[4:], 
				'Property_ID': int(propertyId[4:]), 
				'Prod_Version': productionVersion, 
				'Staging_Version': stgVersion, 
				'Latest_Version': latestVersion,			
				'Product': productId
				}					
			if args:
				for config_env in args:
					config_version = new_row[config_env]
					if config_version is not None:							
						get_version = self.wrapper.getVersionDetails(propertyId,groupId,contractId,str(config_version))										
						if 'versions' in get_version:
							for item in get_version['versions']['items']:
								new_row[config_env + '_Updated_User'] = item['updatedByUser']
								new_row[config_env + '_Updated_Time'] = item['updatedDate']
								if productId == None:
									productId = item['productId'][4:]
					else:
						new_row[config_env + '_Updated_User'] = 'No_' + config_env
						new_row[config_env + '_Updated_Time'] = 'No_' + config_env	
			new_row['Product'] = productId
			version = new_row['Latest_Version']
			if ('Prod_Version' in new_row) and (new_row['Prod_Version'] is not None):
				version = new_row['Prod_Version']
			else:
				if ('Staging_Version' in new_row) and (new_row['Staging_Version'] is not None):
					version = new_row['Staging_Version']	
			new_row['Hostnames'] = self.getPropertyHostDetails(new_row['Group_ID'],new_row['Contract_ID'],new_row['Property_ID'], str(version))
			new_row['Origins'] = self.getPropertyOriginDetails(new_row['Group_ID'],new_row['Contract_ID'],new_row['Property_ID'], str(version))
			new_row['Behaviors'] = self.getBehaviorDetails()
			new_row['CP_Codes'] = '['+self.getCPCodeDetails()+']'
			property_behaviors = new_row['Behaviors']
			list_grp_configs.append(new_row)
			if productionVersion is not None:
				propertyVersion = productionVersion
			elif stgVersion is not None:
				propertyVersion = stgVersion 
			else :
				propertyVersion = latestVersion
			available_behaviors = self.wrapper.getavailableBehavior(propertyId, str(propertyVersion),contractId,  groupId)			
			if 'behaviors' in available_behaviors:
				
				for b in available_behaviors['behaviors']['items']:
					
					enabled = False
			
					if b['name'] in property_behaviors:
						enabled = True
					new_row = {
					'Config_Name': config_details['propertyName'],
					'Behaviors': b['name'], 
					'Enabled': enabled
					}
					list_grp_behaviors.append(new_row)

		return
	
	def GroupsWorker(self, workType,group,main_list=None,second_list=None):
		"""
			Worker for multithreads for property functions, cpcode functions, edgehosts due to high number of groups per 
			account,

			Keyword arguments:
					workType 	<= Type of function to be execute [property, cpcode , edgehosts]
					group		<= Dataframe containing list of account groups
					main_list 	<= list passed down by maint thread to append results
					second_list	<= secondary list passed down by main thread to append results

			Return type:
				None
		"""
		groupId = group['groupId']

		if 'contractIds' in group:	
					
			for contractId in group['contractIds']:
			
				if workType == 'properties':
					location_result = self.wrapper.getProperties(groupId, contractId)
					if 'properties' in location_result:
						with concurrent.futures.ThreadPoolExecutor(max_workers=self.maxThreads) as executor:
							for config_details in location_result['properties']['items']:
								executor.submit(self.PropertyWorker,main_list,second_list,config_details)		
				elif workType == 'cpcodes':
					cpcodes = self.wrapper.getCPCodes(groupId, contractId)
					with concurrent.futures.ThreadPoolExecutor(max_workers=self.maxThreads) as executor:
						for cp in cpcodes['cpcodes']['items']:
							products = []
							for product in cp['productIds']:
								products.append(product[4:])
								new_row = {
									'Group_ID': int(groupId[4:]),
									'Contract_ID': contractId[4:], 
									'CP_Code_ID': int(cp['cpcodeId'][4:]), 
									'CP_Code_Name': cp['cpcodeName'], 
									'CP_Code_Products': "|".join(products) 
									}
								
								if new_row not in main_list:
									self.log.debug("Fetched data for CPcode: '{0}'".format(cp['cpcodeId'][4:]))
									main_list.append(new_row)
				elif workType == 'edgehost':
					if 'contractIds' in group:
						for contractId in group['contractIds']:
							if contractId in second_list:
								break
							second_list.append(contractId)
							edgeHostNames = self.wrapper.getEdgeHostNames(groupId, contractId,'hapi')
							for edgeHostName in edgeHostNames['edgeHostnames']:
								slot = None
								if 'slotNumber' in edgeHostName:
									slot = edgeHostName['slotNumber']
								productID = None
								if 'productId' in edgeHostName:
									productID = edgeHostName['productId']
								IPv = None
								if 'ipVersionBehavior' in edgeHostName:
									IPv = edgeHostName['ipVersionBehavior']
								eMap = None
								if 'map' in edgeHostName:
									eMap = edgeHostName['map']
								new_row = {
									'Group_ID': int(groupId[4:]),
									'Contract_ID': contractId[4:], 
									'Edge_Host_ID': edgeHostName['edgeHostnameId'], 
									'Edge_Host_Name': edgeHostName['recordName']+'.'+edgeHostName['dnsZone'], 
									"Edge_Host_Domain_Suffix":edgeHostName['dnsZone'], 
									"Secure":edgeHostName['securityType'], 
									"IPVersion":IPv,
									"Product_ID":productID,
									"Map":eMap,
									"Slot":slot
									}
									
								main_list.append(new_row)
						

					
		self.log.debug("Fetched configs for group: '{0}'".format(groupId[4:]))
		return None

	def printCPcodes(self):
		"""
			orchestrates mutlithreading by using the GroupsWorker function to populate CPcode data	

			Keyword arguments:
					None

			Return type:
				None
		"""

		lst_cpcodes = []
		columns = ["Group_ID", "Contract_ID", "CP_Code_ID", "CP_Code_Name", "CP_Code_Products"]
		df_cpcodes = pd.DataFrame(columns=columns)
		with concurrent.futures.ThreadPoolExecutor(max_workers=self.maxThreads) as executor:
			for group in self.groups['groups']['items']:
				groupId = group['groupId']
				executor.submit(self.GroupsWorker,'cpcodes',group,lst_cpcodes)
		df_cpcodes= df_cpcodes.append(lst_cpcodes, ignore_index=True)
		
		self.dfs['cpcodes'] = df_cpcodes	

	def printPropertiesDetails(self, *args):
		"""
			orchestrates mutlithreading by using the GroupsWorker function to populate property data
			
			Return type:
				None
		"""

		self.log.debug('Start time is {0}'.format(strftime("%Y-%m-%d %H:%M:%S", gmtime())))
		self.log.debug('generating config data.....')
		columns = [ 
			"Config_Name",
			"Group_ID",
			"Contract_ID",
			"Property_ID",
			"Prod_Version",
			"Staging_Version",
			"Latest_Version",
			"Product",
			"Prod_Version_Updated_User",
			"Prod_Version_Updated_Time",
			"Staging_Version_Updated_User",
			"Staging_Version_Updated_Time",
			"Latest_Version_Updated_User",
			"Latest_Version_Updated_Time",
			"Hostnames",
			"Origins",
			
			"Behaviors",
			"CP_Codes"
			] 
		list_properties = []
		list_behavior = []
		df_property = pd.DataFrame(columns=columns)
		with concurrent.futures.ThreadPoolExecutor(max_workers=self.maxThreads) as executor:
			for group in self.groups['groups']['items']:
				executor.submit(self.GroupsWorker,'properties',group,list_properties,list_behavior)
		
		df_property= df_property.append(list_properties, ignore_index=True)
		tmp = df_property[ ['Config_Name' ,
		 					'Property_ID',
							"Group_ID", 
							
							"Contract_ID", 
							"Product" ,
							"Prod_Version", 
							"Prod_Version_Updated_User",
							"Prod_Version_Updated_Time", 
							"Latest_Version", 
							"Latest_Version_Updated_User", 
							"Latest_Version_Updated_Time", 
							"Staging_Version" , 
							"Staging_Version_Updated_User" , 
							"Staging_Version_Updated_Time", 
							"Behaviors", 
							"CP_Codes"
							]]
		

		self.log.debug('properties.csv generated')   
		self.dfs['properties']=tmp
		
		
		columns = ["Config_Name", "Behaviors", "Enabled"]
		df_behaviors = pd.DataFrame(columns=columns)
		df_behaviors= df_behaviors.append(list_behavior, ignore_index=True)
		self.dfs['propertiesBehaviors']=df_behaviors
		self.log.debug('properties_behaviors.csv generated') 
	
		self.log.debug('Now fetching origin details...')
		columns = ["Config_Name","Property_ID", "Group_ID", "Contract_ID","Origin_Host_Name", "Origin_Type"]
		df_origins = pd.DataFrame(columns=columns)
	
		for index, row in df_property.iterrows():
			for o in row['Origins']:
				new_row = {
					'Config_Name':row['Config_Name'],
					'Property_ID':row['Property_ID'],
					'Group_ID':row['Group_ID'],
					'Contract_ID':row['Contract_ID'],
					'Origin_Host_Name':o['hostname'],
					'Origin_Type':o['originType']
				}
				df_origins = df_origins.append(new_row, ignore_index=True)
		self.dfs['origins'] = df_origins
		self.log.debug('origins.csv generated') 
		self.log.debug('Fetching Origin details is now complete')
		self.printPropertyHostNames(df_property)

		return
	
	@functools.lru_cache()
	def _resource_path(self,grp_id, grp_path=None):
		"""
			Creates a directory like structure groups, to visualize resource location.
			

			Keyword arguments:
					grp_id
					grp_path

			Return type:
				grp_path	<= Resource Path within Account
		"""
		grp_id = int(grp_id)
		grp_parent = self.groups[self.groups['Group_ID']== grp_id]['Parent'].item()
		if grp_path == None:
			grp_path = self.groups[self.groups['Group_ID']== grp_id]['Group_Name'].item()
		else:
			grp_path = "{0} > {1}".format(self.groups[self.groups['Group_ID']== grp_id]['Group_Name'].item(),grp_path)
		if grp_parent != "None" and grp_parent != None and not np.isnan(grp_parent):
			grp_path = self._resource_path(grp_parent,grp_path)
		return grp_path

	def printPropertyHostNames(self, df_property):
		# now write the host name details
		columns = ["Host_Name", "Defined_CNAMED", "Actual_CNAME"
		, "Secure", "Akamaized","Slot","Config_Name","Property_ID", "Group_ID", "Contract_ID"]
		
		
		df_hosts = pd.DataFrame(columns=columns)
		for index, row in df_property.iterrows():

			for host in row['Hostnames']:
				
				new_row = {
					'Host_Name':host['host'],
					'Defined_CNAMED':host['cname_defined'],
					'Actual_CNAME':host['cname_actual'], 
					'Secure':host["secure"], 
					'Akamaized':host["akamaized"],
					'Slot':host['slot'],
					'Config_Name':row['Config_Name'],
					'Property_ID':int(row['Property_ID']),
					'Group_ID':int(row['Group_ID']),
					'Contract_ID':row['Contract_ID']
					
					
				}
				df_hosts = df_hosts.append(new_row, ignore_index=True)
		
		self.dfs['hostnames']=df_hosts

	def getPropertyHostDetails(self, groupId, contractId, propertyId, propertyVersion):
		"""
			for the property, get the host names, origin names and if the host names are CNAMED to Akamai	
		
			Keyword arguments:
					grp_id
					contractId
					propertyId
					propertyVersion

			Return type:
				hostnames	
		"""
		hostdetailsJSON = self.wrapper.getPropertyHostNames(propertyId, propertyVersion, groupId, contractId)		
		hostnames = []
		
		if 'hostnames' in hostdetailsJSON:
			for hostname in hostdetailsJSON['hostnames']['items']:			
				host = ""
				cname_defined = ""

				if 'cnameFrom' in hostname:
					host = hostname['cnameFrom']
				
				if 'cnameTo' in hostname:
					cname_defined = hostname['cnameTo']
				cname_actual = str(self.getCNAME(host))
				
				slot = None
				# TODO: Not working properly
				if cname_actual == "None":
					isAkamaized = "Unknown"
					secureHostName = "Unknown"
					# slot = "Unknown"
				else:
					isAkamaized = self._isAkamaized(cname_actual)
					secureHostName = self._isESSL(cname_actual)
					if secureHostName is None:
						slot = "None"
						secureHostName = False
					else:

						slot = self.checkSlot(host)
						secureHostName = True

				new_row = { 'host': host, 
					 'cname_defined': cname_defined, 
					 'cname_actual': cname_actual, 
					 'secure' : secureHostName, 
					 'slot': slot,
					 'akamaized': isAkamaized
					}
			
				hostnames.append(new_row)
		return hostnames		

	def getPropertyOriginDetails(self, groupId, contractId, propertyId, propertyVersion):
		"""
		Finds Origins from property and defines origin Type

		returns
			origin_details
		"""
		self.rules = self.wrapper.getConfigRuleTree(propertyId, propertyVersion, groupId, contractId)
		self.origin = Origin_Settings()
		origin_details = self.origin.findOrigins(self.rules)

		#replace origin for GTM with the word GTM
		for origin in origin_details:
			if origin['hostname'].endswith('akadns.net'):
				origin['originType'] = 'GTM'
		
		return origin_details

	def getPropertyCPCodeDetails(self, groupId, contractId, propertyId, propertyVersion):
	
		self.cpcodes = Origin_Settings()
		origin_details = self.cpcodes.findOrigins(self.rules, 'cpCode')

		# now get the property's product type
		return origin_details		

	def getEnrollments(self):
		"""
		get a list enrollments  using CPS API for a contract and returns a list of enrollments 
		"""
		contracts = self.wrapper.getContractNames()
		columns = ["Contract_ID", "Common_Name","Enrollment_ID" ,"Slots","ALT_names", "MustHave_Ciphers", "Preferred_Ciphers", "Deployment_Location", "Certifcate_Type" , "Certifcate_Authority"]
		df_certs = pd.DataFrame(columns=columns)
		#TODO: print ciphers
		for contract in contracts['contracts']['items']:
			enrollment_results = self.wrapper.getEnrollements(contract['contractId'][4:])
			if enrollment_results is not None:
				if 'enrollments' in enrollment_results:
					if len(enrollment_results['enrollments']) >0:
						for i in enrollment_results['enrollments']:
							Enrollment_ID = str(i['location']).split('/')[4]
							
							new_row = {
							'Contract_ID':contract['contractId'][4:],
							'Common_Name':i['csr']['cn'],
							'Enrollment_ID':int(Enrollment_ID),
							'Slots': self.getSlotId(Enrollment_ID),
							'ALT_names':i['csr']['sans'],
							'MustHave_Ciphers':i['networkConfiguration']['mustHaveCiphers'], 
							'Preferred_Ciphers':i['networkConfiguration']['preferredCiphers'],
							'Deployment_Location':i['networkConfiguration'], 
							'Certifcate_Authority':i['ra'], 
							'Certifcate_Type':i['certificateType']
							}
							df_certs = df_certs.append(new_row, ignore_index=True)

		self.dfs['certs'] = df_certs 
		
	def getSlotId(self,enrollementID):
		Enrollment = self.wrapper.getEnrollmentHistory(enrollementID)
		slots = None
		for c in Enrollment['certificates']:
			if c['deploymentStatus'] == 'active':
				slots =  int(str(c['slots']).replace('[', '').replace(']', ''))
				break
		return slots
		
	def printMatchTargets(self,matchTargets):
	
		columns = ["Target_ID", "Type", "Config_ID", "Config_Version", "Default_File", "File_Paths", "APIs","Hostnames","Security_Policy", "Sequence"]
		df_secMatch = pd.DataFrame(columns=columns)
		for mt in matchTargets:
			for webTarget in mt['matchTargets']['websiteTargets']: 
				mtype = None
				if 'type' in webTarget: mtype = webTarget['type']
				hostnames = None
				if 'hostnames' in webTarget: hostnames = webTarget['hostnames']
				configId = None
				if 'configId' in webTarget: configId = webTarget['configId']
				configVersion = None
				if 'configVersion' in webTarget: configVersion = webTarget['configVersion']
				defaultFile = None
				if 'defaultFile' in webTarget: defaultFile = webTarget['defaultFile']
				filePaths = None
				if 'filePaths' in webTarget: filePaths = webTarget['filePaths']
				targetId = None
				if 'targetId' in webTarget: targetId = webTarget['targetId']
				securityPolicy = None
				if 'securityPolicy' in webTarget: securityPolicy = webTarget['securityPolicy']
				sequence = None
				if 'sequence' in webTarget: sequence = webTarget['sequence']
				new_row = {
					"Target_ID":targetId, 
					"Type":mtype, 
					"Config_ID":configId, 
					"Config_Version":configVersion, 
					"Default_File":defaultFile, 
					"File_Paths":filePaths, 
					"APIs":None,
					"Hostnames":hostnames,
					"Security_Policy":securityPolicy, 
					"Sequence":sequence
				}
				df_secMatch = df_secMatch.append(new_row, ignore_index=True)
		self.dfs['secMatch'] = df_secMatch
		return None
	
	def printAppSec(self):
		
		secConfigs = self.getSecConfigs()
		matchTargets = []
		columns = ["AppSec_Config_Name", "AppSec_Config_ID", "AppSec_Type", "AppSec_Target_Product", "AppSec_Hostnames", "AppSec_Production_Version", "AppSec_Staging_Version"]
		df_configs = pd.DataFrame(columns=columns)
		 
		for secConfig in secConfigs['configurations']:
			version = secConfig['latestVersion'] 
			stg_version = None
			prod_version = None
			lst_version = None
			prodHostnames = None
			if ('productionVersion' in secConfig) and (secConfig['productionVersion'] is not None):
				version = secConfig['productionVersion']
			else:
				if ('stagingVersion' in secConfig) and (secConfig['stagingVersion'] is not None):
					version = secConfig['stagingVersion']
					stg_version = secConfig['stagingVersion']

			if 'productionVersion' in secConfig:
				prod_version = secConfig['productionVersion']
			if 'stagingVersion' in secConfig:
				stg_version = secConfig['stagingVersion']
			if 'latestVersion' in secConfig:
				lst_version = secConfig['latestVersion']
			if 'productionHostnames' in secConfig:
				prodHostnames = secConfig['productionHostnames']
			matchTargets.append(self.getSecMatchTargets(secConfig['id'],version ))
			name = None
			if 'name' in secConfig:
				name = secConfig['name']
			
			new_row = {
				'AppSec_Config_Name':name, 
				'AppSec_Config_ID':secConfig['id'], 
				'AppSec_Type':secConfig['fileType'], 
				'AppSec_Target_Product':secConfig["targetProduct"], 
				'AppSec_Hostnames':prodHostnames,
				'AppSec_Production_Version':prod_version,
				'AppSec_Staging_Version':stg_version
				}
			df_configs = df_configs.append(new_row, ignore_index=True)

		self.dfs['secConfigs'] = df_configs
		self.printMatchTargets(matchTargets)
		columns = ["Host_Name","AppSec_Config_Name", "AppSec_Config_ID", "AppSec_Type", 
		"AppSec_Target_Product", "AppSec_Production_Version","AppSec_Policy"]
		df_configByHost = pd.DataFrame(columns=columns)
		for secConfig in secConfigs['configurations']:
			if 'productionHostnames' in secConfig:
				for host in secConfig["productionHostnames"]:
					name = None
					mtype = None
					configId = None
					configVersion = None
					defaultFile = None
					filePaths = []
					targetId = []
					securityPolicies = "Not Protected"
					if 'name' in secConfig:
						name = secConfig['name']
					for mt in matchTargets:
						for webTarget in mt['matchTargets']['websiteTargets']: 
							if secConfig['id'] != webTarget['configId']:
								continue
							if 'hostnames' in webTarget:
								if host not in webTarget['hostnames']:
									continue
							if securityPolicies == "Not Protected":
								for sp in webTarget['securityPolicy']:
									securityPolicies = []
									securityPolicies.append(webTarget['securityPolicy']['policyId'])
							elif 'securityPolicy' in webTarget: 
								for sp in webTarget['securityPolicy']:
									if webTarget['securityPolicy'] not in securityPolicies:
										if securityPolicies == "Not Protected":
											securityPolicies = []
										securityPolicies.append(webTarget['securityPolicy']['policyId'])
					new_row = {
						'Host_Name':host,
						'AppSec_Config_Name':name, 
						'AppSec_Config_ID':secConfig['id'], 
						'AppSec_Type':secConfig['fileType'], 
						'AppSec_Target_Product':secConfig["targetProduct"], 
						'AppSec_Production_Version':secConfig["productionVersion"],
						'AppSec_Policy':securityPolicies
						}
					df_configByHost = df_configByHost.append(new_row, ignore_index=True)
		self.dfs['secConfigByHost'] = df_configByHost
		return
					
	def presentation(self,path=None):
		#TODO: FiX: change product from ID to name
		if path:
			self.outputdir = path

		properties = self.dfs['properties']
		self.groups = self.dfs['groups'] 
		hostnames = self.dfs['hostnames']
		secbyHost = self.dfs['secConfigByHost']

		dat = hostnames.merge(self.groups , on='Group_ID').fillna("None")
		
		dat = hostnames.merge(properties[['Config_Name', 'Product', 'Prod_Version','Staging_Version']], on='Config_Name',how='left').fillna("None")    
		dat = dat.merge(secbyHost,on='Host_Name',how='left').fillna('Not Protected')
		
		dat['Resource_Path'] = dat['Group_ID'].apply(self._resource_path)
		
		dat = dat.rename(columns={"Product": "Product_ID"})

		dat['Product'] = dat['Product_ID'].apply(self._translateProductID)

		dat = dat[['Host_Name','Defined_CNAMED', 'Actual_CNAME', 'Secure','Slot', 'Akamaized', 'Group_ID','Resource_Path', 'Contract_ID', 'Config_Name', 'Property_ID',  'Product_ID', 'Product', 'Prod_Version', 'Staging_Version', 'AppSec_Config_Name', 'AppSec_Config_ID', 'AppSec_Type', 'AppSec_Target_Product', 'AppSec_Production_Version', 'AppSec_Policy', 'AppSec_Target_Product']]
		
		self.dfs['ByHost'] = dat
	
	def _readProductMap(self):
		if self.productMap is None:
			with open('Lib/GCS/productMap.json') as f:
				self.productMap  = json.load(f)

	def mineHar(self,har,lst_firstparty):
		colmms = ['url','host','host-type','protocol','method','status','ext','cpcode','ttl','server','cdn-cache','cdn-cache-parent','cdn-cache-key','cdn-req-id','vary','appOrigin','content-length','content-length-origin','transfer-size','blocked','dns','ssl','connect','send','ttfb','receive','edgeTime','originTime'
		]
		dat_clean = pd.DataFrame(columns=colmms)
		for r in har['log']['entries']:
			u = str(r['request']['url']).split('?')[0]
			host = re.search('://(.+?)/', u, re.IGNORECASE).group(0).replace(':','').replace('/','')
			cachekey = str(self._findHeader(r,'response','x-cache-key','eq'))
			if not cachekey == 'None':
				cachekey = cachekey.split('/')
				cpcode = int(cachekey[3])
				ttl = cachekey[4]
				cdnCache = str(self._findHeader(r,'response','x-cache','eq')).split(' ')[0]
				cdnCacheParent = str(self._findHeader(r,'response','x-cache-remote','eq')).split(' ')[0]
				origin = str(self._findHeader(r,'response','x-cache-key','eq')).split('/')[5]
			else:
				cachekey = "None"
				cpcode = "None"
				ttl = "None"
				cdnCache = "None"
				cdnCacheParent = "None"
				origin = "None"

			ext = re.search(r'(\.[A-Za-z0-9]+$)', u, re.IGNORECASE)
			if any(tld in host for tld in lst_firstparty):
				hostType = 'First Party'
				edgeTime = self._findHeader(r,'cdn-timing','edge','eq')
				originTime = self._findHeader(r,'cdn-timing','origin','eq')
			else:
				hostType = 'Third Party'
				edgeTime = -1
				originTime = -1

			if ext is None:
				ext = "None"
			else:
				ext = ext.group(0).replace('.','') 
			ct = self._findHeader(r,'response','content-length','eq')
			if ct == "None":
				ct = 0
			else:
				ct = int(ct)
			if ext in ['jpg','png']:
				ct_origin = self._findHeader(r,'response','x-im-original-size','eq')
			else:
				ct_origin = self._findHeader(r,'response','x-akamai-ro-origin-size','eq')
			if ct_origin == "None":
				ct_origin = 0
			else:
				ct_origin = int(ct_origin)
			new_row = {
				'url':u,
				'host':host,
				'host-type':hostType,
				'protocol':r['request']['httpVersion'],
				'method':r['request']['method'],
				'status':r['response']['status'],
				'ext':ext,
				'cpcode':cpcode,
				'ttl':ttl,
				'server':str(self._findHeader(r,'response','server','eq')),
				'cdn-cache':cdnCache,
				'cdn-cache-parent':cdnCacheParent,
				'cdn-cache-key':str(self._findHeader(r,'response','x-true-cache-key','eq')),
				'cdn-req-id':str(self._findHeader(r,'response','x-akamai-request-id','eq')),
				'vary':str(self._findHeader(r,'response','vary','eq')),
				'appOrigin':origin,
				'content-length':ct,
				'content-length-origin':ct_origin,
				'transfer-size':r['response']['_transferSize'],
				'blocked':r['timings']['blocked'],
				'dns':r['timings']['dns'],
				'ssl':r['timings']['ssl'],
				'connect':r['timings']['connect'],
				'send':r['timings']['send'],
				'ttfb':r['timings']['wait'],
				'receive':r['timings']['receive'],
				'edgeTime':edgeTime,
				'originTime':originTime
				
				}
			dat_clean = dat_clean.append(new_row,ignore_index=True)
		dat_clean = dat_clean.groupby(colmms).size().reset_index(name='Count')   
		self.dfs['har'] = dat_clean
		return True

	def _findHeader(self,req,headertype,headername,op = None):

		value = "None"
		if headertype == 'response':
			for h in req['response']['headers']:
				if op == 'in':
					if headername in h['name'].lower():
						value = h['value']
						break
				else:
					if headername == h['name'].lower():
						value = h['value']
						
						break
		if headertype == 'cdn-timing':
			value = 0
			for h in req['response']['headers']:
				if op == 'eq':
					if 'server-timing' in h['name'].lower():
						if headername in h['value'].lower():
							
							value = int(h['value'].split(';')[1].split('=')[1])
							break
			if value is None:
				return 0
		return value

	def _translateProductID(self,productID):

		result = self.productMap['product'].get(productID.lower())
		if result is not None:
			return result.get('name')
		else:
			return None

	def clear_cache(self):
		self._resource_path.cache_clear()
		self.wrapper.clear_cache()	

	def getBehaviorDetails(self):
		return ( self.origin.findOrigins(self.rules, 'behaviors') )

	def getCPCodeDetails(self):
		return ", ".join( self.origin.findOrigins(self.rules, 'cpCode') )

	def getCNAME(self, hostname):
		return self.wrapper.getCNAME(hostname)

	def _isESSL(self,hostname):
		return self.wrapper.getEsslCname(hostname)

	def _isAkamaized(self, hostname):
		return self.wrapper.checkIfCDN(hostname)
		
	def checkSlot(self,hostname):
		return self.wrapper.checkSlot(hostname)

	def getSecConfigs(self):
		return self.wrapper.getAppSecConfigurations()

	def getSecMatchTargets(self,configID,version):
		return self.wrapper.getAppSecMatchTargets(configID,version)

	def _writeFiles(self):
		try:
			if self.reportType == 'as':
				with pd.ExcelWriter(self.outputdir+'Summary.xlsx') as writer:  
					self.dfs['ByHost'].to_excel(writer, sheet_name='Host Summary', index=False)
					self.dfs['contracts'].to_excel(writer, sheet_name='contracts', index=False)
					self.dfs['groups'].to_excel(writer, sheet_name='groups', index=False)
					self.dfs['cpcodes'].to_excel(writer, sheet_name='cpcodes', index=False)
					self.dfs['hostnames'].to_excel(writer, sheet_name='hostnames', index=False)
					self.dfs['certs'].to_excel(writer, sheet_name='certs', index=False)
					self.dfs['edgehostnames'].to_excel(writer, sheet_name='edgehostnames', index=False)
					self.dfs['properties'].to_excel(writer, sheet_name='properties', index=False)
					self.dfs['propertiesBehaviors'].to_excel(writer, sheet_name='propertiesBehaviors', index=False)
					self.dfs['origins'].to_excel(writer, sheet_name='origins', index=False)
					self.dfs['secConfigs'].to_excel(writer, sheet_name='secConfigs', index=False)
					self.dfs['secMatch'].to_excel(writer, sheet_name='secMatch', index=False)
					self.dfs['secConfigByHost'].to_excel(writer, sheet_name='secConfigByHost', index=False)			
			elif self.reportType == 'har':
				with pd.ExcelWriter(self.outputdir+'HAR-Summary.xlsx') as writer:  
					self.dfs['har'].to_excel(writer, sheet_name='Request Details', index=False)
		except:
			return False
		return True

	# [START] ACC Reporting API: Offload
	def _ReportingWorker(self,cpcode,rtype,lst_reviewed_cpcodes,lst_reviewed_cpcodes_df):
		if cpcode in lst_reviewed_cpcodes:
			return False
		self.log.info("Gathering offload data for CPcode:'{0}'".format(cpcode))
		lst_reviewed_cpcodes.append(cpcode)
		resultsHits = (self.wrapper.reporting('urlhits-by-url',cpcode,self.startDate,self.endDate,rtype))

		df_hits = pd.DataFrame(resultsHits['data'])
		if len(df_hits.index) <= 0:
			self.log.warning("No Data found for CPcode:'{0}'".format(cpcode))
			return None
		resultsbytes = (self.wrapper.reporting('urlbytes-by-url',cpcode,self.startDate,self.endDate,rtype))
		df_bytes = pd.DataFrame(resultsbytes['data'])

		df_merged= df_hits.merge(df_bytes, on='hostname.url')

		df_merged = df_merged.astype({"allEdgeHits": int,"allOriginHits": int, "allHitsOffload": float,"allEdgeBytes": int, "allOriginBytes": int, "allBytesOffload": float})
		df_merged[self.groupby] = df_merged['hostname.url'].apply(self._getUrlExt)
		df_merged = df_merged.groupby(self.groupby)[["allEdgeHits","allEdgeBytes","allOriginHits","allOriginBytes","allHitsOffload","allBytesOffload"]].agg({'allEdgeHits':'sum','allOriginHits':'sum','allHitsOffload':'mean','allEdgeBytes':'sum','allOriginBytes':'sum','allBytesOffload':'mean'}).reset_index().sort_values(['allEdgeBytes'], ascending=False)

		df_merged['offloadHits'] = df_merged.apply(lambda x: self._getoffload(x.allEdgeHits, x.allOriginHits), axis=1)
		df_merged['offloadBytes'] = df_merged.apply(lambda x: self._getoffload(x.allEdgeBytes, x.allOriginBytes), axis=1)
		
		df_merged['trafficHitPercentage'] = round(df_merged['allEdgeHits']/df_merged['allEdgeHits'].sum()*100,2)
		df_merged['trafficBytePercentage'] = round(df_merged['allEdgeBytes']/df_merged['allEdgeBytes'].sum()*100,2)

		df_merged = df_merged.reset_index(drop=True).sort_values(['trafficBytePercentage'], ascending=False)
		df_merged['CPCODE'] = cpcode
		if df_merged is None:
			self.log.info("No Data found for CPcode: '{0}'".format(cpcode))
			return None
		else:
			lst_reviewed_cpcodes_df.append(df_merged)

	def _writeReport(self, lst_reviewed_cpcodes_df):
		writer = pd.ExcelWriter(self.outputdir+'Offload-Summary.xlsx')
		
		df_summary = self._summarize(lst_reviewed_cpcodes_df)
		df_summary.to_excel(writer, sheet_name='Summary',engine='xlsxwriter',index=False)
		for index, row in df_summary.iterrows():

			for df in lst_reviewed_cpcodes_df:
				if int(df['CPCODE'][0]) == int(row['CPCODE']):
					df.rename(columns={'allHitsOffload':'Offload'}, inplace=True)
					df[[self.groupby,"allEdgeHits","allEdgeBytes","allOriginHits","allOriginBytes",'offloadHits','offloadBytes','trafficHitPercentage','trafficBytePercentage']].to_excel(writer, sheet_name='{0}'.format(df['CPCODE'].iloc[0]),engine='xlsxwriter',index=False)
					
		writer.save()
	
		return
	
	def _enforceformat(self,dateString):

		dateString = dateString.split('-')

		
		if len(dateString[1]) == 1:

			dateString[1] = '0'+dateString[1]
		if len(dateString[2]) == 1:

			start[2] = '0'+dateString[2]
		return "{0}-{1}-{2}".format(dateString[0],dateString[1],dateString[2])
		
	def print_offload(self,lst_cpcodes=None,start=None,end=None):
		
		if lst_cpcodes is None:
			self.printCPcodes()
			lst_cpcodes = self.dfs['cpcodes']['CP_Code_ID']
		sheets = False
		
		lst_reviewed_cpcodes = []
		lst_reviewed_cpcodes_df = []

		rtype = "urlhits-by-url"
		if start is not None and end is not None:
			self.startDate  = self._enforceformat(start)
			self.endDate = self._enforceformat(end)

		else:
			year = datetime.datetime.today().year

			endMonth = datetime.datetime.now().strftime('%m')
			startMonth = datetime.datetime.now() - datetime.timedelta(weeks=4)
			startMonth = startMonth.strftime('%m')

			self.startDate = "{0}-{1}-01".format(datetime.datetime.today().year,startMonth)
			self.endDate = "{0}-{1}-01".format(datetime.datetime.today().year,endMonth)
		
		self.log.info("Report Start-Date '{0}', End-Date '{1}'".format(self.startDate,self.endDate))
		with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
			for cpcode in lst_cpcodes:
				executor.submit(self._ReportingWorker,cpcode,rtype,lst_reviewed_cpcodes,lst_reviewed_cpcodes_df)

		if len(lst_reviewed_cpcodes_df) > 0:
			self._writeReport(lst_reviewed_cpcodes_df)     
			self.log.info("Report successfull, output can be found here: '{0}'".format(self.outputdir+'Offload.xlsx'))
		else:
			self.log.warning("Report unsuccessfull, no CPcode data found.")
	
	def _summarize(self,lst):
		columns = [self.groupby,"allEdgeHits","allEdgeBytes","allOriginHits","allOriginBytes","allHitsOffload","allBytesOffload",'offloadHits','offloadBytes','trafficHitPercentage','trafficBytePercentage','CPCODE']

		df = pd.DataFrame(columns=columns)
		df = df.append(lst, ignore_index=True)
		del df['trafficHitPercentage']
		del df['trafficBytePercentage']
		del df['allHitsOffload']
		del df['allBytesOffload']

		df = df.groupby('CPCODE')[["allEdgeHits","allEdgeBytes","allOriginHits","allOriginBytes",'offloadHits','offloadBytes']].agg({'allEdgeHits':'sum','allOriginHits':'sum','allEdgeBytes':'sum','allOriginBytes':'sum','offloadHits':'sum','offloadBytes':'sum'}).reset_index().sort_values(['allEdgeBytes'], ascending=False)

		df['offloadHits'] =  round(df['offloadHits']/df['allEdgeHits']*100,2)
		df['offloadBytes'] =  round(df['offloadBytes']/df['allEdgeBytes']*100,2)

		df['trafficHitPercentage'] = round((df['allEdgeHits']/df['allEdgeHits'].sum())*100,2)
		df['trafficBytePercentage'] = round((df['allEdgeBytes']/df['allEdgeBytes'].sum())*100,2)

		return df
	
	def _getUrlExt(self,url):
	
		parsed = urlparse(url)
		root, ext = splitext(parsed.path)
		if self.groupby == 'ext':
			if ext == '':
				return 'extensionless'
			return ext[1:]
		else:
			return re.sub(r'^.*?/', '/', root)
				
	
		return ext[1:]
	
	def _getoffload(self,t,x):
		return (t-x)
	
	def _getTotalOffload(self,totalhits,totaloffloadhist):
		return (totaloffloadhist/totalhits)*100

	def _readJson(self,location):
		if not os.path.isfile(location):
			return None
		with open(location, 'r') as f:
			file = json.loads(f.read())
			f.close()
		return file
		
if __name__=="__main__":
	# TODO: remove CP and Group, etc prefix grp_

	parser, args = ArgsParser()

	

	if args['verbose']:
		console = ConsoleLogging()
		console.setLevel("DEBUG")
		console.configure_logging()
	else:
		console = ConsoleLogging()
		console.configure_logging()
	if args['section']:
		obj_agg = Aggregator(console,args,args['section'])
	else:
		obj_agg = Aggregator(console,args)
	if args['type'] != 'har':
		
		# if not args['switchKey']:
		# 	parser.error('--switchKey has required for operation.')
		# else:
		obj_agg.log.info("Getting Account Details")
		if obj_agg.getAccountDetails():	
			if args['type'] == 'as':
				obj_agg.reportType = 'as'
				
				obj_agg.log.info("Starting Account Summary")
				obj_agg.accountSummary()
				obj_agg.clear_cache()
			elif args['type'] == 'os' :
				obj_agg.reportType = 'os'

				obj_agg.log.info("Starting Offload Summary")
				if args['cpcodes']:
					
					if not args['start'] and not args['end']:
						obj_agg.log.info("Performing Analysis for previous month.")
						obj_agg.print_offload(args['cpcodes'])
					else:
						if obj_agg._validateDate(args['start']):
							if obj_agg._validateDate(args['end']):
									obj_agg.print_offload(args['cpcodes'],args['start'],args['end'])
							else:
								parser.error('--end has incorrect data format, should be YYYY-MM-DD.')
						else:
							parser.error('--start has incorrect data format, should be YYYY-MM-DD.')
				else:
					obj_agg.log.info("Performing Account wide Analysis.")
					
					if not args['start'] and not args['end']:
						obj_agg.log.info("Performing Analysis for previous month.")
						obj_agg.print_offload()
					else:
						if obj_agg._validateDate(args['start']):
							if obj_agg._validateDate(args['end']):
									obj_agg.print_offload(None,args['start'],args['end'])
							else:
								parser.error('--end has incorrect data format, should be YYYY-MM-DD.')
						else:
							parser.error('--start has incorrect data format, should be YYYY-MM-DD.')
	else:
		if args['type'] == 'har':
			obj_agg.reportType = 'har'
			obj_agg.log.info("Starting HTTP-Archive Summary")
			obj_agg.createFolder("HTTP-Archive")
			
			if args['domain']:
				if args['file']:
					lst_firstparty = []

					obj_json = obj_agg._readJson(args['file']) 
					if obj_json is None:
						obj_agg.log.error("No file found in '{0}'".format(args['file']))
					else:
						obj_agg.log.info("HAR file read.")
						lst_firstparty.append(args['domain'])
						if args['first_parties']:
							lst_firstparty = args['first_parties']
						obj_agg.log.info("Extracting data from HAR.")
						obj_agg.mineHar(obj_json,lst_firstparty)
						obj_agg.log.info("Writing Report.")
						obj_agg._writeFiles()
						obj_agg.log.info("Report successfull, output can be found here '{0}'".format(obj_agg.outputdir+'HAR-Summary.xlsx'))
				else:
					parser.error('--file is needed for file locations.')

				pass
			else:
				parser.error('--domain is needed for HTTP-Archive.')

	obj_agg.clear_cache()



		
	
	
