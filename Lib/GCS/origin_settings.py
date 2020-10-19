import json
import sys, pprint
if sys.version_info < (3,0):
	from sets import Set 

class Origin_Settings:
	"""
	Class that recursively finds and prints origin names
	"""	
	def __init__(self):
		"""
		Initialize an empty array to hold the names of the origins
		"""
		self.origins=[]	
		self.cpcodes = []	
		if sys.version_info < (3,0):
			self.behaviors = Set()
		else:
			self.behaviors = set()

	def findOrigin(self,rule):
		for behavior in rule['behaviors']:			
			if behavior['name']=="origin":	
				#by default the origin type and host name is set to None. This is to cover badly configured / unfinished configurations.
				origin_type = None
				origin_hostname = None		
				if 'originType' in behavior['options']:
					origin_type = behavior['options']['originType']
					#print('hey the buggy code is' )
					#pprint.pprint(behavior['options'])
					if origin_type=='CUSTOMER' and 'hostname' in behavior['options'] :
						origin_hostname = behavior['options']['hostname']				
					elif 'netStorage' in behavior['options']:
						origin_hostname = behavior['options']['netStorage']['downloadDomainName']
					else:
						origin_type = "None"		
						origin_hostname = "None"					
				self.origins.append( {"originType": origin_type, "hostname": origin_hostname} )
	
	def findCPCodes(self, rule):				
		for behavior in rule['behaviors']:						
			if behavior['name']=="cpCode":
				#print("hey the buggy codes is " , behavior)
				if 'value' in behavior['options']:					
					behavior = behavior['options']['value']
					if behavior is not None:
						self.cpcodes.append(
						{ \
							'id': behavior['id'] if 'id' in behavior else None,\
							'desciption': behavior['description'] if 'description' in behavior else None, \
							'products': "|".join(behavior['products']) if 'products' in behavior else None
						}
					)
					else: 
						self.cpcodes.append({'id':None,'description':None,'products':None})
				else:
					self.cpcodes.append({'id':None,'description':None,'products':None})

	def findBehaviors(self, rule):
		for behavior in rule['behaviors']:
			self.behaviors.add( behavior['name'] )


	def findChildren(self,rules,nodeType="origin"):	
		"""
			Keep finding child nodes. A child is identified by the key name 'children'. If a child is found, call the function back with the sub-tree starting at child node.

			Keyword arguments:
				rules: PAPI rules tree
				nodeType : origin / cpCode. This will call the rules to find the CP Code or the origin
			
			Return parameters:
				None. Interally, it sets the object self.origins for the origin name or the self.cpcodes for the CP Codes.
		"""	
		if rules['children']:
			for child in rules['children']:				
				#keep looping for each child				
				self.findChildren(child, nodeType)
				#when complete, check if origin is present
				if nodeType=="origin":
					self.findOrigin(child)	
				elif nodeType == "cpCode":
					self.findCPCodes(child)
				elif nodeType == "behaviors":					
					self.findBehaviors(child)

		
	def getOrigins(self, format="json"):
		"""
			Gets back the origin names
		"""
		'''
		if format=="json":
			print json.dumps(self.origins)
		else:
			print self.origins
		'''
		return self.origins

	def getCpCodes(self, format="json"):
		"""
			Gets back the CP Code names
		"""
		'''
		if format=="json":
			print json.dumps(self.cpcodes)
		else:
			print self.cpcodes
		'''			
		cpcodes = set()
		for cpcode in self.cpcodes:
			cpcodes.add( str(cpcode['id']) )
		return list(cpcodes)

	def getBehaviors(self, format="json"):
		return list(self.behaviors)

	def getOrigins(self, format="json"):
		return self.origins

	def findOrigins(self, rules, nodeType='origin'):
		"""
		Calls the right function to find the origins or CP Codes.

			Keyword arguments: 
				nodeType: Defines the kind of tree search we are executing. By default, we are looking for origins.
		"""
		if 'rules' in rules:						
			if nodeType=="origin":
				self.findOrigin(rules['rules'])
			if nodeType=="cpCode":						
				self.findCPCodes(rules['rules'])
			if nodeType=="behaviors":
				self.findBehaviors(rules['rules'])
			self.findChildren(rules['rules'],nodeType)
		
		if nodeType=="cpCode":
			#return self.cpcodes
			return self.getCpCodes()
		elif nodeType=="origin":
			return self.origins
		elif nodeType=="behaviors":
			return list(self.behaviors)

if __name__=="__main__":
	f = open('rules.json')
	rules = json.loads(f.read())
	o = Origin_Settings()	
	o.findOrigins(rules, 'cpCode')

	print (o.getCpCodes())
