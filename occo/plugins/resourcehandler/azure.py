### Copyright 2014, MTA SZTAKI, www.sztaki.hu
###
### Licensed under the Apache License, Version 2.0 (the "License");
### you may not use this file except in compliance with the License.
### You may obtain a copy of the License at
###
###    http://www.apache.org/licenses/LICENSE-2.0
###
### Unless required by applicable law or agreed to in writing, software
### distributed under the License is distributed on an "AS IS" BASIS,
### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
### See the License for the specific language governing permissions and
### limitations under the License.

""" Azure implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Herr Attila <h.attila19@hotmail.com>
"""

from __future__ import absolute_import
import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
from occo.exceptions import SchemaError

#import azurerm
import azure
from azure.storage.blob import BlockBlobService
import base64
import time
import requests
import adal

__all__ = ['AzureResourceHandler']

PROTOCOL_ID = 'azure'
STATE_MAPPING = {
    'creating'      : status.PENDING,
    'VM starting'   : status.PENDING,
    'VM running'       : status.READY,
    'succeeded'     : status.READY,
    'Deleting'      : status.SHUTDOWN,
    'VM deallocating'  : status.SHUTDOWN,
    'VM deallocated'   : status.SHUTDOWN,
    'VM stopped'   : status.SHUTDOWN,
    'Provisioning failed'      : status.TMP_FAIL,
    'error'        : status.TMP_FAIL
}

log = logging.getLogger('occo.resourcehandler.azure')

azure_rm_endpoint = 'https://management.azure.com'

authentication_endpoint = 'https://login.microsoftonline.com/'
#Azure Management API endpoint
resource  = 'https://management.core.windows.net/'

BASE_API = '2015-01-01'
STORAGE_API = '2015-06-15'
COMP_API = '2016-03-30'
NETWORK_API = '2016-03-30'
INSIGHTS_API = '2014-04-01'
MEDIA_API = '2015-10-01'

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    def create_vm(self, access_token, subscription_id, resource_group, vm_name, vm_size, publisher, offer, sku, version,
              storage_account, os_uri, username, password, nic_id, location, customData, image_uri=None, osType="Linux"):
	endpoint = ''.join([azure_rm_endpoint,
                '/subscriptions/', subscription_id,
                '/resourceGroups/', resource_group,
                '/providers/Microsoft.Compute/virtualMachines/', vm_name,
                '?api-version=', COMP_API])
	if image_uri:
	    body = ''.join(['{"name": "', vm_name,
                '","location": "', location,
                '","properties": { "hardwareProfile": {',
                '"vmSize": "', vm_size,
                '"},',
                '"storageProfile": { "osDisk": {',
                                        '"name": "myosdisk1",',
                                        '"osType": "', osType,
                                        '","caching": "ReadWrite",',
                                        '"createOption": "FromImage",',
                                        '"image": { "uri": "', image_uri,
                                         '"},',
                                        '"vhd": { "uri": "', os_uri,
                                '" }}}, ',
                '"osProfile": {',
                '"computerName": "', vm_name,
                '", "adminUsername": "', username,
                '", "adminPassword": "', password,
                '", "customData": "', customData,
                # '", linuxConfigurpuation": { "disablePasswordAuthentication": "', disablePassAuth,
                # '", ssh": { "publicKeys": [ {'
                # '"path": "', keyPathOnVm,
                # '", keyData": "', PublicKey,
                # '"} ] } }'
                '" }, "networkProfile": {',
                '"networkInterfaces": [{"id": "', nic_id,
                '", "properties": {"primary": true}}]}}}'])
	else:
	    body = ''.join(['{"name": "', vm_name,
                '","location": "', location,
                '","properties": { "hardwareProfile": {',
                '"vmSize": "', vm_size,
                '"},"storageProfile": { "imageReference": { "publisher": "', publisher,
                '","offer": "', offer,
                '","sku": "', sku,
                '","version": "', version,
                '"},"osDisk": { "name": "myosdisk1","vhd": {',
                '"uri": "', os_uri,
                '" }, "caching": "ReadWrite", "createOption": "fromImage" }}, "osProfile": {',
                '"computerName": "', vm_name,
                '", "adminUsername": "', username,
                '", "adminPassword": "', password,
                '", "customData": "', customData,
                # '", linuxConfigurpuation": { "disablePasswordAuthentication": "', disablePassAuth,
                # '", ssh": { "publicKeys": [ {'
                # '"path": "', keyPathOnVm,
                # '", keyData": "', PublicKey,
                # '"} ] } }'
                '" }, "networkProfile": {',
                '"networkInterfaces": [{"id": "', nic_id,
                '", "properties": {"primary": true}}]}}}'])
	return self.do_put(endpoint, body, access_token)

    # create_public_ip(access_token, subscription_id, resource_group)
    # list the public ip addresses in a resource group
    def create_public_ip(self, access_token, subscription_id, resource_group, public_ip_name, location, dns_label=None):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/publicIPAddresses/', public_ip_name,
                        '?api-version=', NETWORK_API])
	if dns_label != None:
	    body = ''.join(['{"location": "', location,
                    '", "properties": {"publicIPAllocationMethod": "Dynamic", "dnsSettings": {',
                    '"domainNameLabel": "', dns_label, '"}}}'])
	else:
	    body = ''.join(['{"location": "', location,
                    '", "properties": {"publicIPAllocationMethod": "Dynamic",}}'])
        return self.do_put(endpoint, body, access_token)

    # create_nic(access_token, subscription_id, resource_group, nic_name, public_ip_id, subnet_id, location)
    # create a network interface with an associated public ip address
    def create_nic(self, access_token, subscription_id, resource_group, nic_name, subnet_id, location, nsg_id, public_ip_id=None):
	endpoint = ''.join([azure_rm_endpoint,
                    '/subscriptions/', subscription_id,
                    '/resourceGroups/', resource_group,
                    '/providers/Microsoft.Network/networkInterfaces/', nic_name,
                    '?api-version=', NETWORK_API])
	if public_ip_id != None:
	    body = ''.join(['{ "location": "', location,
                    '", "properties": { "networkSecurityGroup":{ "id": "', nsg_id,
				'" }, "ipConfigurations": [{ "name": "ipconfig1", "properties": {',
                		    '"privateIPAllocationMethod": "Dynamic", "publicIPAddress": {',
                		    '"id": "', public_ip_id,
                		    '" }, "subnet": { "id": "', subnet_id,
                    '" } } } ] } }'])
	else:
	    body = ''.join(['{ "location": "', location,
                    '", "properties": { "networkSecurityGroup":{ "id": "', nsg_id,
				'" }, "ipConfigurations": [{ "name": "ipconfig1", "properties": {',
                    '"privateIPAllocationMethod": "Dynamic",',
                    '"subnet": { "id": "', subnet_id,
                    '" } } } ] } }'])
	return self.do_put(endpoint, body, access_token)

    # do_put(endpoint, body, access_token)
    # do an HTTP PUT request and return JSON
    def do_put(self, endpoint, body, access_token):
	headers = {"content-type": "application/json", "Authorization": 'Bearer ' + access_token}
	return requests.put(endpoint, data=body, headers=headers)
    
    # get_access_token(tenant_id, application_id, application_secret)
    # get an Azure access token using the adal library
    def get_access_token(self, tenant_id, application_id, application_secret):
	context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
	token_response = context.acquire_token_with_client_credentials(resource, application_id,
                                                                   application_secret)
	return token_response.get('accessToken')

    @wet_method()
    def _create_azure_node(self, resource_dict, auth_data, name_unique, os_uri, customdata):
	access_token = self.get_access_token(resource_dict.get("tenant_id"), 
                                                auth_data.get("application_id"), 
						auth_data.get("application_secret"))
	#log.debug("Access token: %s",str(access_token))

        # # create public IP address
	public_ip_id = None
	if resource_dict.get("public_ip_needed", False):
	    log.debug('Creating public IP address: ' + "occo-pip-"+name_unique)
	    pip_return = self.create_public_ip(access_token, resource_dict.get("subscription_id"), resource_dict.get("resource_group"),
                                            "occo-pip-"+name_unique, resource_dict.get("vnet_location"),
					    dns_label=resource_dict.get("public_dns_name", None))
	    log.debug("create_pip RETURN: %s", str(pip_return.json()))
	    log.debug("pip_return STATUS CODE: %s", str(pip_return.status_code))
	    #Ha sikeres a pip keszites, akkor folytassa, maskulonben ERROR
	    if pip_return.status_code == 201:
		public_ip_id = pip_return.json().get('id', None)
		log.debug('public_ip_id = ' + str(public_ip_id))
	    else:
		#RAISE EXCEPTION KELL!
		log.debug('Error:' + pip_return.json().get("error").get("message"))

	time.sleep(2)       # 2 masodperc varakozas (kb. ezalatt elkesziti)

	# # create NIC
	
	log.debug('Creating NIC: ' + "occo-nic-"+name_unique)
	subnet_id = "{0}/subnets/{1}".format(resource_dict.get("vnet_id"), resource_dict.get("subnet_name"))
	nic_return = self.create_nic(access_token, resource_dict.get("subscription_id"), resource_dict.get("resource_group"),
					 "occo-nic-"+name_unique, subnet_id , resource_dict.get("vnet_location"),resource_dict.get("nsg_id"), public_ip_id=public_ip_id)
	log.debug('NIC_RETURN : ' +str(nic_return.json()))
	log.debug('NIC_status_code : ' +str(nic_return.status_code))
	if nic_return.status_code == 201:
	    nic_id = nic_return.json().get('id')
	    log.debug('NIC_ID : ' +str(nic_id))
	else:
	        # HIBA RAISE ERROR 
	    log.debug('Error:' + nic_return.json().get("error").get("message"))
	

	time.sleep(2)       # 2 masodperc varakozas (kb. ezalatt elkesziti)


	
	vm_return = self.create_vm(access_token, 
                                     resource_dict.get("subscription_id"), 
                                     resource_dict.get("resource_group"), 
                                      "occo-vm-" + name_unique,
				     resource_dict.get("vm_size"), 
                                     resource_dict.get("publisher"), 
                                     resource_dict.get("offer"), 
                                     resource_dict.get("sku"),
                                     resource_dict.get("version"), 
                                     resource_dict.get("storage_name"), 
                                     os_uri, 
                                     resource_dict.get("username"),
				     resource_dict.get("password"), 
                                     nic_id, 
                                     resource_dict.get("vm_location"), 
                                     customdata,
				     image_uri=resource_dict.get("image_uri", None)
				     )
	log.debug("vm_return: %s", str(vm_return.json()))

	#vm_getinfo =''
	#while ((str(vm_getinfo).find('ProvisioningState/succeeded')) == -1):
	#    vm_getinfo = azurerm.get_vm_instance_view(access_token, resource_dict.get("subscription_id"), resource_dict.get("resource_group"), vm_name_unique)
	#    if vm_getinfo.status_code == 200:
	#	if (len(vm_getinfo.json().get("statuses")) == 1):
        #	    vm_getinfo = "Code:{0} \t Display status:{1}".format(vm_getinfo.json().get("statuses")[0].get("code"),vm_getinfo.json().get("statuses")[0].get("displayStatus"))
	#	else:
	#	    vm_getinfo = "Code:{0} \t Display status:{1}".format(vm_getinfo.json()["statuses"][0]["code"], vm_getinfo.json().get("statuses")[1].get("displayStatus"))

	#	log.debug("VM STATUS:%s",str(vm_getinfo))
	#	time.sleep(5)
	#    else:
	#	log.debug("get_vm_instance STATUS CODE: %s", str(vm_getinfo.status_code))
	#	log.debug("get_vm_instance JSON: %s", str(vm_getinfo.json()))
	#	break
	time.sleep(3)
	return dict(vm_name_unique="occo-vm-"+name_unique, nic_id=nic_id, public_ip_id=public_ip_id)


    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
                  resource_handler.name, self.resolved_node_definition['name'])

        log.debug("Azure: CreateNode")
	log.debug("Endpoint: %s",str(resource_handler.endpoint))
	log.debug("Auth_data: %s",str(resource_handler.auth_data))
	log.debug("Resource section: %s",str(self.resolved_node_definition.get("resource",dict())))
	log.debug("Resolved node definition: %s",str(self.resolved_node_definition))

	resource_dict = self.resolved_node_definition.get("resource",dict())
	name_unique = "{0}-{1}-{2}-{3}".format(
					self.resolved_node_definition.get("infra_name")[0:14],
					self.resolved_node_definition.get("infra_id")[0:13],
                                       self.resolved_node_definition.get("name")[0:14],
                                       self.resolved_node_definition.get("node_id")[0:13])
	name_unique = name_unique.replace("_", "-")
        log.debug("Azure name_unique: %s",name_unique)
	os_uri = "http://{0}.blob.core.windows.net/{1}/osdisk.vhd".format(resource_dict.get("storage_name"), "occo-vm-"+name_unique)

	#image_uri = "https://tesztgroupdisk.blob.core.windows.net/vhds/kezzel-keszitett201691011256.vhd"
	customdata = base64.b64encode(self.resolved_node_definition.get("context"))
	log.debug("customdata:"+customdata)
	log.debug("vm_name: occo-vm-"+name_unique)
	log.debug("os_uri:"+os_uri)

	instance_id_dict = self._create_azure_node(self.resolved_node_definition.get("resource",dict()), resource_handler.auth_data, name_unique, os_uri, customdata)

        log.debug("[%s] Done; vm_id = %r", resource_handler.name, str(instance_id_dict))
        return instance_id_dict

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data    

    # delete_vm(access_token, subscription_id, resource_group, vm_name)
    # delete a virtual machine
    def delete_vm(self, access_token, subscription_id, resource_group, vm_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Compute/virtualMachines/', vm_name,
                        '?api-version=', COMP_API])
	return self.do_delete(endpoint, access_token)

    #  !!!!!!!!!!!!!!!!!!!!!!!!!!!!! Instance nezet !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    def get_vm_instance_view(self, access_token, subscription_id, resource_group, vm_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Compute/virtualMachines/', vm_name,
                        '/InstanceView?api-version=', COMP_API])
	return self.do_get(endpoint, access_token)


    #NIC torlese
    def delete_nic(self, access_token, subscription_id, resource_group, nic_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/networkInterfaces/', nic_name,
                        '?api-version=', NETWORK_API])
	return self.do_delete(endpoint, access_token)


#PIP torlese
    def delete_pip(self, access_token, subscription_id, resource_group, pip_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/publicIPAddresses/', pip_name,
                        '?api-version=', NETWORK_API])
	return self.do_delete(endpoint, access_token)

    # do_delete(endpoint, access_token)
    # do an HTTP DELETE request and return JSON
    def do_delete(self, endpoint, access_token):
	headers = {"Authorization": 'Bearer ' + access_token}
	return requests.delete(endpoint, headers=headers)

	# do_get(endpoint, access_token)
    # do an HTTP GET request and return JSON
    def do_get(self, endpoint, access_token):
	headers = {"Authorization": 'Bearer ' + access_token}
	return requests.get(endpoint, headers=headers)

    # get_access_token(tenant_id, application_id, application_secret)
    # get an Azure access token using the adal library
    def get_access_token(self, tenant_id, application_id, application_secret):
	context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
	token_response = context.acquire_token_with_client_credentials(resource, application_id,
                                                                   application_secret)
	return token_response.get('accessToken')


    @wet_method()
    def _drop_azure_node(self, auth_data, instance_data):
	access_token = self.get_access_token(instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("tenant_id"),
                                                auth_data.get("application_id"), 
						auth_data.get("application_secret"))

	rmreturn = self.delete_vm(access_token,
				     instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("subscription_id"),
				     instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("resource_group"),
				     instance_data.get("instance_id").get("vm_name_unique"))
	log.debug("Delete response kod:%s",str(rmreturn.status_code))
	#if rmreturn.status_code != (202 or 200):
	    # hiba dobas!
	
	# amig a rest api valasz nem tartalmaz 'not found'-ot addig getstatus
	# kifejteni...
	#Ha vegzett a VM torlessel, akkor a hatrahagyott containert kitoroljuk a storage accountban
	vm_getinfo =''
	while ((str(vm_getinfo).find('not found')) == -1):
	    vm_getinfo = self.get_vm_instance_view(access_token,
						     instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("subscription_id"),
						     instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("resource_group"),
						     instance_data.get("instance_id").get("vm_name_unique"))
	    if vm_getinfo.status_code == 200:
		if (len(vm_getinfo.json().get("statuses")) == 1):
        	    vm_getinfo = "Code:{0} \t Display status:{1}".format(vm_getinfo.json().get("statuses")[0].get("code"),vm_getinfo.json().get("statuses")[0].get("displayStatus"))
		else:
		    vm_getinfo = "Code:{0} \t Display status:{1}".format(vm_getinfo.json().get("statuses")[0].get("code"), vm_getinfo.json().get("statuses")[1].get("displayStatus"))
		log.debug("VM STATUS:%s",str(vm_getinfo))
		time.sleep(5)
	    else:
		log.debug("Status code: %s",str(vm_getinfo.status_code))
		break
	# Kulonben AzureHttpError , a container hasznalatban van!
	if not instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("keep_vhd_on_destroy", False):
	    try:
	        block_blob_service = BlockBlobService(account_name=instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("storage_name"),
					      account_key=instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("storage_key"))
	        delete_container = block_blob_service.delete_container(instance_data.get("instance_id").get("vm_name_unique"))
	        log.debug("CONTAINER DELETE:%s",str(delete_container))
	    except azure.common.AzureHttpError as ex:
	        log.debug("Error: %s",str(ex.message))
	#sikeres a torles, ha (delete_container = True es rmreturn.status_code = 200 or 202)

	#Delete NIC
	delete_nic_info = self.delete_nic(access_token,
					  instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("subscription_id"),
					  instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("resource_group"),
					  instance_data.get("instance_id").get("nic_id").rsplit('/').pop())
	#nic_name kinyerese a nic_id-bol, feldaraboljuk az id-t '/' karakter szerint, majd az utolso lesz a nev, pop()
	log.debug("Delete_nic_info.status_code: %s:",str(delete_nic_info.status_code))
	if delete_nic_info.status_code != 202:
	    #akkor error
	    log.debug("Delete_nic_info.status_code: %s:",str(delete_nic_info.status_code))
	
	time.sleep(5) #max ennyi ido alatt torli ki a NIC-et

	#Delete PIP, if the node has got public IP
	if (instance_data.get("instance_id").get("public_ip_id") != None):
	    delete_pip_info = self.delete_pip(access_token,
					    instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("subscription_id"),
					    instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("resource_group"),
					    instance_data.get("instance_id").get("public_ip_id").rsplit('/').pop())
	log.debug("Delete_pip_info.status_code: %s",str(delete_pip_info))
	    if (delete_pip_info.status_code != 202):
		#akkor error
		log.debug("Delete_pip_info.status_code: %s",str(delete_pip_info))


	return

    def perform(self, resource_handler):
        instance_id = self.instance_data['instance_id']
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])
        
        log.debug("Azure: DropNode")
	log.debug("Endpoint: %s",str(resource_handler.endpoint))
	log.debug("Auth_data: %s",str(resource_handler.auth_data))
	log.debug("Instance data: %s",str(self.instance_data))

	self._drop_azure_node(resource_handler.auth_data, self.instance_data)


        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    

#  !!!!!!!!!!!!!!!!!!!!!!!!!!!!! Instance nezet !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    def get_vm_instance_view(self, access_token, subscription_id, resource_group, vm_name):
        endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Compute/virtualMachines/', vm_name,
                        '/InstanceView?api-version=', COMP_API])
        return self.do_get(endpoint, access_token)
    # do_get(endpoint, access_token)
    # do an HTTP GET request and return JSON
    def do_get(self, endpoint, access_token):
	headers = {"Authorization": 'Bearer ' + access_token}
	return requests.get(endpoint, headers=headers)

    # get_access_token(tenant_id, application_id, application_secret)
    # get an Azure access token using the adal library
    def get_access_token(self, tenant_id, application_id, application_secret):
	context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
	token_response = context.acquire_token_with_client_credentials(resource, application_id,
                                                                   application_secret)
	return token_response.get('accessToken')


    @wet_method('VM running')
    def _getstate_azure_node(self, auth_data, instance_data):
	access_token = self.get_access_token(instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("tenant_id"),
                                                auth_data.get("application_id"), 
						auth_data.get("application_secret"))
	#log.debug("Acc token:"+access_token)

	inst_state = ''
	vm_getinfo_code = ''
	vm_getinfo_disp = ''
	vm_getinfo = self.get_vm_instance_view(access_token, 
						  instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("subscription_id"), 
						  instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("resource_group"),
						   instance_data.get("instance_id").get("vm_name_unique"))
	if vm_getinfo.status_code == 200:
	    if (len(vm_getinfo.json().get("statuses")) == 1):
		vm_getinfo_code = vm_getinfo.json().get("statuses")[0].get("code")
		vm_getinfo_disp = vm_getinfo.json().get("statuses")[0].get("displayStatus")
	    else:
		vm_getinfo_code = vm_getinfo.json().get("statuses")[0].get("code")
		vm_getinfo_disp = vm_getinfo.json().get("statuses")[1].get("displayStatus")
	    log.debug("VM STATUS CODE:%s",str(vm_getinfo_code))
	    log.debug("VM STATUS DISP:%s",str(vm_getinfo_disp))
	else:
	    inst_state = "error"
	    log.debug("HIBA HTTP KOD: %s",str(vm_getinfo.status_code))
	    log.debug("HIBA HTTP Error message: %s",str(vm_getinfo.json().get("error").get("message")))
	
	if (vm_getinfo_code.find('creating') != -1):
	    inst_state = "creating"
	elif (vm_getinfo_code.find('succeeded') != -1) and (vm_getinfo_disp.find('running') != -1):
	    inst_state = "succeeded"
	else:
	    inst_state = vm_getinfo_disp[vm_getinfo_disp.find(':')+1:]

	return inst_state
    
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring node state %r",
                  resource_handler.name, self.instance_data['node_id'])

        log.debug("Azure: GetState")
	log.debug("Endpoint: %s",str(resource_handler.endpoint))
	log.debug("Auth_data: %s",str(resource_handler.auth_data))
	log.debug("Instance data: %s",str(self.instance_data))

	inst_state = self._getstate_azure_node(resource_handler.auth_data, self.instance_data)

        try:
            retval = STATE_MAPPING[inst_state]
        except KeyError:
            raise NotImplementedError('Unknown Azure state', inst_state)
        else:
            log.debug("[%s] Done; azure_state=%r; status=%r",
                      resource_handler.name, inst_state, retval)
            return retval

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    #get_nics(access_token, subscription_id) ez kell a vm publikus ip cimenek lekeresehez
    def get_nic(self, access_token, subscription_id, resource_group, nic_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/',
                        '/networkInterfaces/', nic_name,
                        '?api-version=', NETWORK_API])
	return self.do_get(endpoint, access_token)
    # do_get(endpoint, access_token)
    # do an HTTP GET request and return JSON
    def do_get(self, endpoint, access_token):
	headers = {"Authorization": 'Bearer ' + access_token}
	return requests.get(endpoint, headers=headers)

    # get_public_ip(access_token, subscription_id, resource_group)
    # get details about the named public ip address
    def get_public_ip(self, access_token, subscription_id, resource_group, ip_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/',
                        'publicIPAddresses/', ip_name,
                        '?api-version=', NETWORK_API])
        return self.do_get(endpoint, access_token)
    
    # get_access_token(tenant_id, application_id, application_secret)
    # get an Azure access token using the adal library
    def get_access_token(self, tenant_id, application_id, application_secret):
	context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
	token_response = context.acquire_token_with_client_credentials(resource, application_id,
                                                                   application_secret)
	return token_response.get('accessToken')

    @wet_method('127.0.0.1')
    def _getIpaddress_azure_node(self, auth_data, instance_data):
	access_token = self.get_access_token(instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("tenant_id"),
                                                auth_data.get("application_id"),
						auth_data.get("application_secret")) 
	#log.debug("Acc token:"+access_token)

	nic_subscription_id = ''
	nic_resource_group = ''
	nic_name_idx = ''
	vm_nic_name = ''
	#vm_nic_id = instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("nic_id")
	vm_nic_id = instance_data.get("instance_id").get("nic_id")
	
	vm_nic_id_splitted = str.split(str(vm_nic_id), '/')
        log.debug("Vm_nics_ids_splitted: %s",str(vm_nic_id_splitted))
        log.debug("Vm_nics_id_splitted: %s",str(len(vm_nic_id_splitted)))

        nic_subscription_id = vm_nic_id_splitted[2]
        nic_resource_group = vm_nic_id_splitted[4]
	#Ideiglenes megoldas
	#Problema: eredetileg a NIC ID-t egy GetStatus hivassal kertem le, de mivel a felhasznalo ezt megadja a node_definition.yaml-ben
		# ezert innen ki lehet venni.
		# eredeti megoldasban a NIC ID tartalmazott egy "primary vagy secondary" jelzot is
	#Megoldas: egy if ag berakasa, ha talal primary v secondary szot akkor eredetileg dolgozza fel a NIC ID-t
	if (vm_nic_id.find('primary') != -1) or (vm_nic_id.find('secondary') != -1):
	    nic_name_idx = vm_nic_id_splitted[8].index(',')
	    vm_nic_name = (str(vm_nic_id_splitted[8][0:nic_name_idx]).strip('\''))  # string formazas
	
        else:
	    vm_nic_name = vm_nic_id_splitted[8]
	log.debug("vm_nic_name: %s",str(vm_nic_name))
        # network REST API hivas a megfelelo nic-re (vagy nic-ekre)
	out_string = ""
	private_ip = ""
        private_ip_allocm = ""
        private_ip_ver = ""
        public_ip = ""
        public_ip_data = []
        public_ip_name = []
        public_ip_id = ''
        public_ip_rsg = []  # resource group kell a get_public_ip hivashoz
	public_ip_subid = []

	ip_data = [] #nyers adat, amit az API valaszol

	ip_data = self.get_nic(access_token, nic_subscription_id, nic_resource_group, vm_nic_name).json()
	log.debug("ip_data NYERS: %s",str(ip_data))
	ip_data = ip_data.get("properties", dict()).get("ipConfigurations")
	log.debug("ip_data properties/ipConfigurations: %s",str(ip_data))

	log.debug("ip_data hossza: %s",str(len(ip_data[0].get("properties", dict()))))
	log.debug("ip_data tartalma: %s",str(ip_data[0].get("properties", dict())))

	if len(ip_data[0].get("properties", dict())) == 7:
	    private_ip = (str(ip_data[0].get("properties", dict()).get("privateIPAddress")).strip('u'))
	    log.debug("private_ip: %s",str(private_ip))
	    public_ip_id = (str(ip_data[0].get("properties", dict()).get("publicIPAddress", dict()).get("id")))
    	else:
    	    private_ip = (str(ip_data[0].get("properties", dict()).get("privateIPAddress")).strip('u'))
    	    public_ip_id = ''
	
	log.debug("public_ip_id: %s",str(public_ip_id))
	# Fel kell dolgozni a public ip id-jat
	public_ip_id_splitted = []
	# ha van a NIC-hez publikus IP rendelve
        if len(public_ip_id) > 0:
    	    public_ip_id_splitted = (str(public_ip_id).split('/'))
	    log.debug("Public_ip_id_splitted: %s",str(public_ip_id_splitted))
    	    public_ip_subid = (public_ip_id_splitted[2])
    	    public_ip_rsg = (public_ip_id_splitted[4])
    	    public_ip_name = (public_ip_id_splitted[8])
    	

	    log.debug("public_ip_subid: %s",str(public_ip_subid))
	    # print(public_ip_rsg)
	    # print(public_ip_name)

	    #Get information about a public IP address hivas
	    #for i in range(len(public_ip_name)):
    	    #    public_ip.append(self.get_public_ip(access_token, public_ip_subid[i],public_ip_rsg[i],public_ip_name[i]).json()["properties"]["ipAddress"])

	    # #Formazas
	    # for i in range(len(public_ip)):
    	    # print(public_ip_name[i] + ' Public IP: ' + public_ip[i])
	    public_ip_raw = str(self.get_public_ip(access_token, public_ip_subid,public_ip_rsg,public_ip_name).json())
	    log.debug("public_ip_ NYERS: %s",str(public_ip_raw))
	    public_ip = self.get_public_ip(access_token, public_ip_subid,public_ip_rsg,public_ip_name).json().get("properties", dict()).get("ipAddress", None)
	    
	#Nincs public IP a NIC-hez rendelve
        else:
	    public_ip = None
	log.debug("public ip: %s",str(public_ip))

	return coalesce(public_ip, private_ip)
    
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring IP address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])
       
        log.debug("Azure: GetIpAddress")
	log.debug("Endpoint: %s",str(resource_handler.endpoint))
	log.debug("Auth_data: %s",str(resource_handler.auth_data))
	log.debug("Instance data: %s",str(self.instance_data))

        address = self._getIpaddress_azure_node(resource_handler.auth_data, self.instance_data)
	return address
        

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    #get_nics(access_token, subscription_id) ez kell a vm publikus ip cimenek lekeresehez
    def get_nic(self, access_token, subscription_id, resource_group, nic_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/',
                        '/networkInterfaces/', nic_name,
                        '?api-version=', NETWORK_API])
	return self.do_get(endpoint, access_token)
    # do_get(endpoint, access_token)
    # do an HTTP GET request and return JSON
    def do_get(self, endpoint, access_token):
	headers = {"Authorization": 'Bearer ' + access_token}
	return requests.get(endpoint, headers=headers)

    # get_public_ip(access_token, subscription_id, resource_group)
    # get details about the named public ip address
    def get_public_ip(self, access_token, subscription_id, resource_group, ip_name):
	endpoint = ''.join([azure_rm_endpoint,
                        '/subscriptions/', subscription_id,
                        '/resourceGroups/', resource_group,
                        '/providers/Microsoft.Network/',
                        'publicIPAddresses/', ip_name,
                        '?api-version=', NETWORK_API])
        return self.do_get(endpoint, access_token)

    # get_access_token(tenant_id, application_id, application_secret)
    # get an Azure access token using the adal library
    def get_access_token(self, tenant_id, application_id, application_secret):
	context = adal.AuthenticationContext(authentication_endpoint + tenant_id)
	token_response = context.acquire_token_with_client_credentials(resource, application_id,
                                                                   application_secret)
	return token_response.get('accessToken')

    @wet_method('127.0.0.1')
    def _getaddress_azure_node(self, auth_data, instance_data):
	access_token = self.get_access_token(instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("tenant_id"),
                                                auth_data.get("application_id"), 
						auth_data.get("application_secret"))
	#log.debug("Acc token:"+access_token)

	nic_subscription_id = ''
	nic_resource_group = ''
	nic_name_idx = ''
	vm_nic_name = ''
	#vm_nic_id = instance_data.get("resolved_node_definition", dict()).get("resource",dict()).get("nic_id")
	vm_nic_id = instance_data.get("instance_id").get("nic_id")

	vm_nic_id_splitted = str.split(str(vm_nic_id), '/')
        log.debug("Vm_nics_ids_splitted: %s",str(vm_nic_id_splitted))
        log.debug("Vm_nics_id_splitted: %s",str(len(vm_nic_id_splitted)))

        nic_subscription_id = vm_nic_id_splitted[2]
        nic_resource_group = vm_nic_id_splitted[4]
	#Ideiglenes megoldas
	#Problema: eredetileg a NIC ID-t egy GetStatus hivassal kertem le, de mivel a felhasznalo ezt megadja a node_definition.yaml-ben
		# ezert innen ki lehet venni.
		# eredeti megoldasban a NIC ID tartalmazott egy "primary vagy secondary" jelzot is
	#Megoldas: egy if ag berakasa, ha talal primary v secondary szot akkor eredetileg dolgozza fel a NIC ID-t
	if (vm_nic_id.find('primary') != -1) or (vm_nic_id.find('secondary') != -1):
	    nic_name_idx = vm_nic_id_splitted[8].index(',')
	    vm_nic_name = (str(vm_nic_id_splitted[8][0:nic_name_idx]).strip('\''))  # string formazas
	
        else:
	    vm_nic_name = vm_nic_id_splitted[8]
	log.debug("vm_nic_name: %s",str(vm_nic_name))
        # network REST API hivas a megfelelo nic-re (vagy nic-ekre)
	out_string = ""
	private_ip = ""
        private_ip_allocm = ""
        private_ip_ver = ""
        public_ip = ""
        public_ip_data = []
        public_ip_name = []
        public_ip_id = ''
        public_ip_rsg = []  # resource group kell a get_public_ip hivashoz
	public_ip_subid = []
	public_dns = ""

	ip_data = [] #nyers adat, amit az API valaszol

	ip_data = self.get_nic(access_token, nic_subscription_id, nic_resource_group, vm_nic_name).json()
	log.debug("ip_data NYERS: %s",str(ip_data))
	ip_data = ip_data.get("properties", dict()).get("ipConfigurations")
	log.debug("ip_data properties/ipConfigurations: %s",str(ip_data))

	log.debug("ip_data hossza: %s",str(len(ip_data[0].get("properties", dict()))))
	log.debug("ip_data tartalma: %s",str(ip_data[0].get("properties", dict())))

	if len(ip_data[0].get("properties", dict())) == 7:
	    private_ip = (str(ip_data[0].get("properties", dict()).get("privateIPAddress")).strip('u'))
	    log.debug("private_ip: %s",str(private_ip))
	    public_ip_id = (str(ip_data[0].get("properties", dict()).get("publicIPAddress", dict()).get("id")))
    	else:
    	    private_ip = (str(ip_data[0].get("properties", dict()).get("privateIPAddress")).strip('u'))
    	    public_ip_id = ''
	
	log.debug("public_ip_id: %s",str(public_ip_id))
	# Fel kell dolgozni a public ip id-jat
	public_ip_id_splitted = []
	# ha van a NIC-hez publikus IP rendelve
        if len(public_ip_id) > 0:
    	    public_ip_id_splitted = (str(public_ip_id).split('/'))
	    log.debug("Public_ip_id_splitted: %s",str(public_ip_id_splitted))
    	    public_ip_subid = (public_ip_id_splitted[2])
    	    public_ip_rsg = (public_ip_id_splitted[4])
    	    public_ip_name = (public_ip_id_splitted[8])
    	

	    log.debug("public_ip_subid: %s",str(public_ip_subid))
	    # print(public_ip_rsg)
	    # print(public_ip_name)

	    #Get information about a public IP address hivas
	    #for i in range(len(public_ip_name)):
    	    #    public_ip.append(self.get_public_ip(access_token, public_ip_subid[i],public_ip_rsg[i],public_ip_name[i]).json()["properties"]["ipAddress"])

	    # #Formazas
	    # for i in range(len(public_ip)):
    	    # print(public_ip_name[i] + ' Public IP: ' + public_ip[i])
	    public_ip_raw = str(self.get_public_ip(access_token, public_ip_subid,public_ip_rsg,public_ip_name).json())
	    log.debug("public_ip_ NYERS: %s",str(public_ip_raw))
	    public_dns = self.get_public_ip(access_token, public_ip_subid,public_ip_rsg,public_ip_name).json().get("properties", dict()).get("dnsSettings", dict()).get("fqdn", None)
	    log.debug("DNS nev: %s",str(public_dns))
	    public_ip = self.get_public_ip(access_token, public_ip_subid,public_ip_rsg,public_ip_name).json().get("properties", dict()).get("ipAddress", None)

	#Else, nincs public IP es public DNS a NIC-hez rendelve
        else:
	    public_ip = None
	log.debug("public ip: %s",str(public_ip))

	return coalesce(public_dns,
                        public_ip,
                        private_ip)
    
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])

        log.debug("Azure: GetAddress")
	log.debug("Endpoint: %s",str(resource_handler.endpoint))
	log.debug("Auth_data: %s",str(resource_handler.auth_data))
	log.debug("Instance data: %s",str(self.instance_data))
	
	address = self._getaddress_azure_node(resource_handler.auth_data, self.instance_data) 
	return address

@factory.register(ResourceHandler, PROTOCOL_ID)
class AzureResourceHandler(ResourceHandler):
    def __init__(self, endpoint, auth_data, 
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else endpoint
        self.endpoint = endpoint
        self.auth_data = auth_data

    def cri_create_node(self, resolved_node_definition):
        return CreateNode(resolved_node_definition)

    def cri_drop_node(self, instance_data):
        return DropNode(instance_data)

    def cri_get_state(self, instance_data):
        return GetState(instance_data)
    
    def cri_get_address(self, instance_data):
        return GetAddress(instance_data)
    
    def cri_get_ip_address(self, instance_data):
        return GetIpAddress(instance_data)

    def perform(self, instruction):
        instruction.perform(self)

@factory.register(RHSchemaChecker, PROTOCOL_ID)
class AzureSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "subscription_id", "tenant_id", "storage_name", "storage_key",
                         "vnet_id", "vnet_location", "nsg_id", "subnet_name", "resource_group", "vm_location", "vm_size",
                         "publisher", "offer", "sku", "version", "username", "password", "customdata"]
        self.opt_keys = ["public_ip_needed", "public_dns_name", "image_uri",  "keep_vhd_on_destroy"]
    def perform_check(self, data):
        missing_keys = RHSchemaChecker.get_missing_keys(self, data, self.req_keys)
        if missing_keys:
            msg = "Missing key(s): " + ', '.join(str(key) for key in missing_keys)
            raise SchemaError(msg)
        valid_keys = self.req_keys + self.opt_keys
        invalid_keys = RHSchemaChecker.get_invalid_keys(self, data, valid_keys)
        if invalid_keys:
            msg = "Unknown key(s): " + ', '.join(str(key) for key in invalid_keys)
            raise SchemaError(msg)
        return True
