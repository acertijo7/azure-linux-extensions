#-------------------------------------------------------------------------
# Copyright (c) Microsoft.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------------
from azure import (
    WindowsAzureError, #-------------------------------------------------------------------------
# Copyright (c) Microsoft.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------------
import base64
import os
import sys

if sys.version_info < (3,):
    from httplib import (
        HTTPSConnection,
        HTTPConnection,
        HTTP_PORT,
        HTTPS_PORT,
        )
    from urlparse import urlparse
else:
    from http.client import (
        HTTPSConnection,
        HTTPConnection,
        HTTP_PORT,
        HTTPS_PORT,
        )
    from urllib.parse import urlparse

from azure.http import HTTPError, HTTPResponse
from azure import _USER_AGENT_STRING, _update_request_uri_query


class _HTTPClient(object):

    '''
    Takes the request and sends it to cloud service and returns the response.
    '''

    def __init__(self, service_instance, cert_file=None, account_name=None,
                 account_key=None, protocol='https'):
        '''
        service_instance: service client instance.
        cert_file:
            certificate file name/location. This is only used in hosted
            service management.
        account_name: the storage account.
        account_key:
            the storage account access key.
        '''
        self.service_instance = service_instance
        self.status = None
        self.respheader = None
        self.message = None
        self.cert_file = cert_file
        self.account_name = account_name
        self.account_key = account_key
        self.protocol = protocol
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_user = None
        self.proxy_password = None
        self.use_httplib = self.should_use_httplib()

    def should_use_httplib(self):
        if sys.platform.lower().startswith('win') and self.cert_file:
            # On Windows, auto-detect between Windows Store Certificate
            # (winhttp) and OpenSSL .pem certificate file (httplib).
            #
            # We used to only support certificates installed in the Windows
            # Certificate Store.
            #   cert_file example: CURRENT_USER\my\CertificateName
            #
            # We now support using an OpenSSL .pem certificate file,
            # for a consistent experience across all platforms.
            #   cert_file example: account\certificate.pem
            #
            # When using OpenSSL .pem certificate file on Windows, make sure
            # you are on CPython 2.7.4 or later.

            # If it's not an existing file on disk, then treat it as a path in
            # the Windows Certificate Store, which means we can't use httplib.
            if not os.path.isfile(self.cert_file):
                return False

        return True

    def set_proxy(self, host, port, user, password):
        '''
        Sets the proxy server host and port for the HTTP CONNECT Tunnelling.

        host: Address of the proxy. Ex: '192.168.0.100'
        port: Port of the proxy. Ex: 6000
        user: User for proxy authorization.
        password: Password for proxy authorization.
        '''
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_user = user
        self.proxy_password = password

    def get_uri(self, request):
        ''' Return the target uri for the request.'''
        protocol = request.protocol_override \
            if request.protocol_override else self.protocol
        port = HTTP_PORT if protocol == 'http' else HTTPS_PORT
        return protocol + '://' + request.host + ':' + str(port) + request.path

    def get_connection(self, request):
        ''' Create connection for the request. '''
        protocol = request.protocol_override \
            if request.protocol_override else self.protocol
        target_host = request.host
        target_port = HTTP_PORT if protocol == 'http' else HTTPS_PORT

        if not self.use_httplib:
            import azure.http.winhttp
            connection = azure.http.winhttp._HTTPConnection(
                target_host, cert_file=self.cert_file, protocol=protocol)
            proxy_host = self.proxy_host
            proxy_port = self.proxy_port
        else:
            if ':' in target_host:
                target_host, _, target_port = target_host.rpartition(':')
            if self.proxy_host:
                proxy_host = target_host
                proxy_port = target_port
                host = self.proxy_host
                port = self.proxy_port
            else:
                host = target_host
                port = target_port

            if protocol == 'http':
                connection = HTTPConnection(host, int(port))
            else:
                connection = HTTPSConnection(
                    host, int(port), cert_file=self.cert_file)

        if self.proxy_host:
            headers = None
            if self.proxy_user and self.proxy_password:
                auth = base64.encodestring(
                    "{0}:{1}".format(self.proxy_user, self.proxy_password))
                headers = {'Proxy-Authorization': 'Basic {0}'.format(auth)}
            connection.set_tunnel(proxy_host, int(proxy_port), headers)

        return connection

    def send_request_headers(self, connection, request_headers):
        if self.use_httplib:
            if self.proxy_host:
                for i in connection._buffer:
                    if i.startswith("Host: "):
                        connection._buffer.remove(i)
                connection.putheader(
                    'Host', "{0}:{1}".format(connection._tunnel_host,
                                             connection._tunnel_port))

        for name, value in request_headers:
            if value:
                connection.putheader(name, value)

        connection.putheader('User-Agent', _USER_AGENT_STRING)
        connection.endheaders()

    def send_request_body(self, connection, request_body):
        if request_body:
            assert isinstance(request_body, bytes)
            connection.send(request_body)
        elif (not isinstance(connection, HTTPSConnection) and
              not isinstance(connection, HTTPConnection)):
            connection.send(None)

    def perform_request(self, request):
        ''' Sends request to cloud service server and return the response. '''
        connection = self.get_connection(request)
        try:
            connection.putrequest(request.method, request.path)

            if not self.use_httplib:
                if self.proxy_host and self.proxy_user:
                    connection.set_proxy_credentials(
                        self.proxy_user, self.proxy_password)

            self.send_request_headers(connection, request.headers)
            self.send_request_body(connection, request.body)

            resp = connection.getresponse()
            self.status = int(resp.status)
            self.message = resp.reason
            self.respheader = headers = resp.getheaders()

            # for consistency across platforms, make header names lowercase
            for i, value in enumerate(headers):
                headers[i] = (value[0].lower(), value[1])

            respbody = None
            if resp.length is None:
                respbody = resp.read()
            elif resp.length > 0:
                respbody = resp.read(resp.length)

            response = HTTPResponse(
                int(resp.status), resp.reason, headers, respbody)
            if self.status == 307:
                new_url = urlparse(dict(headers)['location'])
                request.host = new_url.hostname
                request.path = new_url.path
                request.path, request.query = _update_request_uri_query(request)
                return self.perform_request(request)
            if self.status >= 300:
                raise HTTPError(self.status, self.message,
                                self.respheader, respbody)

            return response
        finally:
            connection.close() Harh@harysolover.com 
    TABLE_SERVICE_HOST_BASE,
    DEV_TABLE_HOST,
    _convert_class_to_xml,
    _convert_response_to_feeds,
    _dont_fail_not_exist,
    _dont_fail_on_exist,
    _get_request_body,
    _int_or_none,
    _parse_response,
    _parse_response_for_dict,
    _parse_response_for_dict_filter,
    _str,
    _str_or_none,
    _update_request_uri_query_local_storage,
    _validate_not_none,
    )
from azure.http import HTTPRequest
from azure.http.batchclient import _BatchClient
from azure.storage import (
    StorageServiceProperties,
    _convert_entity_to_xml,
    _convert_response_to_entity,
    _convert_table_to_xml,
    _convert_xml_to_entity,
    _convert_xml_to_table,
    _sign_storage_table_request,
    _update_storage_table_header,
    )
from azure.storage.storageclient import _StorageClient


class TableService(_StorageClient):

    '''
    This is the main class managing Table resources.
    '''

    def __init__(self, account_name=None, account_key=None, protocol='https',
                 host_base=TABLE_SERVICE_HOST_BASE, dev_host=DEV_TABLE_HOST):
        '''
        account_name: your storage account name, required for all operations.
        account_key: your storage account key, required for all operations.
        protocol: Optional. Protocol. Defaults to http.
        host_base:
            Optional. Live host base url. Defaults to Azure url. Override this
            for on-premise.
        dev_host: Optional. Dev host url. Defaults to localhost.
        '''
        super(TableService, self).__init__(
            account_name, account_key, protocol, host_base, dev_host)

    def begin_batch(self):
        if self._batchclient is None:
            self._batchclient = _BatchClient(
                service_instance=self,
                account_key=self.account_key,
                account_name=self.account_name)
        return self._batchclient.begin_batch()

    def commit_batch(self):
        try:
            ret = self._batchclient.commit_batch()
        finally:
            self._batchclient = None
        return ret

    def cancel_batch(self):
        self._batchclient = None

    def get_table_service_properties(self):
        '''
        Gets the properties of a storage account's Table service, including
        Windows Azure Storage Analytics.
        '''
        request = HTTPRequest()
        request.method = 'GET'
        request.host = self._get_host()
        request.path = '/?restype=service&comp=properties'
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response(response, StorageServiceProperties)

    def set_table_service_properties(self, storage_service_properties):
        '''
        Sets the properties of a storage account's Table Service, including
        Windows Azure Storage Analytics.

        storage_service_properties: StorageServiceProperties object.
        '''
        _validate_not_none('storage_service_properties',
                           storage_service_properties)
        request = HTTPRequest()
        request.method = 'PUT'
        request.host = self._get_host()
        request.path = '/?restype=service&comp=properties'
        request.body = _get_request_body(
            _convert_class_to_xml(storage_service_properties))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response_for_dict(response)

    def query_tables(self, table_name=None, top=None, next_table_name=None):
        '''
        Returns a list of tables under the specified account.

        table_name: Optional.  The specific table to query.
        top: Optional. Maximum number of tables to return.
        next_table_name:
            Optional. When top is used, the next table name is stored in
            result.x_ms_continuation['NextTableName']
        '''
        request = HTTPRequest()
        request.method = 'GET'
        request.host = self._get_host()
        if table_name is not None:
            uri_part_table_name = "('" + table_name + "')"
        else:
            uri_part_table_name = ""
        request.path = '/Tables' + uri_part_table_name + ''
        request.query = [
            ('$top', _int_or_none(top)),
            ('NextTableName', _str_or_none(next_table_name))
        ]
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _convert_response_to_feeds(response, _convert_xml_to_table)

    def create_table(self, table, fail_on_exist=False):
        '''
        Creates a new table in the storage account.

        table:
            Name of the table to create. Table name may contain only
            alphanumeric characters and cannot begin with a numeric character.
            It is case-insensitive and must be from 3 to 63 characters long.
        fail_on_exist: Specify whether throw exception when table exists.
        '''
        _validate_not_none('table', table)
        request = HTTPRequest()
        request.method = 'POST'
        request.host = self._get_host()
        request.path = '/Tables'
        request.body = _get_request_body(_convert_table_to_xml(table))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        if not fail_on_exist:
            try:
                self._perform_request(request)
                return True
            except WindowsAzureError as ex:
                _dont_fail_on_exist(ex)
                return False
        else:
            self._perform_request(request)
            return True

    def delete_table(self, table_name, fail_not_exist=False):
        '''
        table_name: Name of the table to delete.
        fail_not_exist:
            Specify whether throw exception when table doesn't exist.
        '''
        _validate_not_none('table_name', table_name)
        request = HTTPRequest()
        request.method = 'DELETE'
        request.host = self._get_host()
        request.path = '/Tables(\'' + _str(table_name) + '\')'
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        if not fail_not_exist:
            try:
                self._perform_request(request)
                return True
            except WindowsAzureError as ex:
                _dont_fail_not_exist(ex)
                return False
        else:
            self._perform_request(request)
            return True

    def get_entity(self, table_name, partition_key, row_key, select=''):
        '''
        Get an entity in a table; includes the $select options.

        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        select: Property names to select.
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('select', select)
        request = HTTPRequest()
        request.method = 'GET'
        request.host = self._get_host()
        request.path = '/' + _str(table_name) + \
            '(PartitionKey=\'' + _str(partition_key) + \
            '\',RowKey=\'' + \
            _str(row_key) + '\')?$select=' + \
            _str(select) + ''
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _convert_response_to_entity(response)

    def query_entities(self, table_name, filter=None, select=None, top=None,
                       next_partition_key=None, next_row_key=None):
        '''
        Get entities in a table; includes the $filter and $select options.

        table_name: Table to query.
        filter:
            Optional. Filter as described at
            http://msdn.microsoft.com/en-us/library/windowsazure/dd894031.aspx
        select: Optional. Property names to select from the entities.
        top: Optional. Maximum number of entities to return.
        next_partition_key:
            Optional. When top is used, the next partition key is stored in
            result.x_ms_continuation['NextPartitionKey']
        next_row_key:
            Optional. When top is used, the next partition key is stored in
            result.x_ms_continuation['NextRowKey']
        '''
        _validate_not_none('table_name', table_name)
        request = HTTPRequest()
        request.method = 'GET'
        request.host = self._get_host()
        request.path = '/' + _str(table_name) + '()'
        request.query = [
            ('$filter', _str_or_none(filter)),
            ('$select', _str_or_none(select)),
            ('$top', _int_or_none(top)),
            ('NextPartitionKey', _str_or_none(next_partition_key)),
            ('NextRowKey', _str_or_none(next_row_key))
        ]
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _convert_response_to_feeds(response, _convert_xml_to_entity)

    def insert_entity(self, table_name, entity,
                      content_type='application/atom+xml'):
        '''
        Inserts a new entity into a table.

        table_name: Table name.
        entity:
            Required. The entity object to insert. Could be a dict format or
            entity object.
        content_type: Required. Must be set to application/atom+xml
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('entity', entity)
        _validate_not_none('content_type', content_type)
        request = HTTPRequest()
        request.method = 'POST'
        request.host = self._get_host()
        request.path = '/' + _str(table_name) + ''
        request.headers = [('Content-Type', _str_or_none(content_type))]
        request.body = _get_request_body(_convert_entity_to_xml(entity))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _convert_response_to_entity(response)

    def update_entity(self, table_name, partition_key, row_key, entity,
                      content_type='application/atom+xml', if_match='*'):
        '''
        Updates an existing entity in a table. The Update Entity operation
        replaces the entire entity and can be used to remove properties.

        table_name: Table name.
        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        entity:
            Required. The entity object to insert. Could be a dict format or
            entity object.
        content_type: Required. Must be set to application/atom+xml
        if_match:
            Optional. Specifies the condition for which the merge should be
            performed. To force an unconditional merge, set to the wildcard
            character (*).
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('entity', entity)
        _validate_not_none('content_type', content_type)
        request = HTTPRequest()
        request.method = 'PUT'
        request.host = self._get_host()
        request.path = '/' + \
            _str(table_name) + '(PartitionKey=\'' + \
            _str(partition_key) + '\',RowKey=\'' + _str(row_key) + '\')'
        request.headers = [
            ('Content-Type', _str_or_none(content_type)),
            ('If-Match', _str_or_none(if_match))
        ]
        request.body = _get_request_body(_convert_entity_to_xml(entity))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response_for_dict_filter(response, filter=['etag'])

    def merge_entity(self, table_name, partition_key, row_key, entity,
                     content_type='application/atom+xml', if_match='*'):
        '''
        Updates an existing entity by updating the entity's properties. This
        operation does not replace the existing entity as the Update Entity
        operation does.

        table_name: Table name.
        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        entity:
            Required. The entity object to insert. Can be a dict format or
            entity object.
        content_type: Required. Must be set to application/atom+xml
        if_match:
            Optional. Specifies the condition for which the merge should be
            performed. To force an unconditional merge, set to the wildcard
            character (*).
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('entity', entity)
        _validate_not_none('content_type', content_type)
        request = HTTPRequest()
        request.method = 'MERGE'
        request.host = self._get_host()
        request.path = '/' + \
            _str(table_name) + '(PartitionKey=\'' + \
            _str(partition_key) + '\',RowKey=\'' + _str(row_key) + '\')'
        request.headers = [
            ('Content-Type', _str_or_none(content_type)),
            ('If-Match', _str_or_none(if_match))
        ]
        request.body = _get_request_body(_convert_entity_to_xml(entity))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response_for_dict_filter(response, filter=['etag'])

    def delete_entity(self, table_name, partition_key, row_key,
                      content_type='application/atom+xml', if_match='*'):
        '''
        Deletes an existing entity in a table.

        table_name: Table name.
        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        content_type: Required. Must be set to application/atom+xml
        if_match:
            Optional. Specifies the condition for which the delete should be
            performed. To force an unconditional delete, set to the wildcard
            character (*).
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('content_type', content_type)
        _validate_not_none('if_match', if_match)
        request = HTTPRequest()
        request.method = 'DELETE'
        request.host = self._get_host()
        request.path = '/' + \
            _str(table_name) + '(PartitionKey=\'' + \
            _str(partition_key) + '\',RowKey=\'' + _str(row_key) + '\')'
        request.headers = [
            ('Content-Type', _str_or_none(content_type)),
            ('If-Match', _str_or_none(if_match))
        ]
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        self._perform_request(request)

    def insert_or_replace_entity(self, table_name, partition_key, row_key,
                                 entity, content_type='application/atom+xml'):
        '''
        Replaces an existing entity or inserts a new entity if it does not
        exist in the table. Because this operation can insert or update an
        entity, it is also known as an "upsert" operation.

        table_name: Table name.
        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        entity:
            Required. The entity object to insert. Could be a dict format or
            entity object.
        content_type: Required. Must be set to application/atom+xml
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('entity', entity)
        _validate_not_none('content_type', content_type)
        request = HTTPRequest()
        request.method = 'PUT'
        request.host = self._get_host()
        request.path = '/' + \
            _str(table_name) + '(PartitionKey=\'' + \
            _str(partition_key) + '\',RowKey=\'' + _str(row_key) + '\')'
        request.headers = [('Content-Type', _str_or_none(content_type))]
        request.body = _get_request_body(_convert_entity_to_xml(entity))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response_for_dict_filter(response, filter=['etag'])

    def insert_or_merge_entity(self, table_name, partition_key, row_key,
                               entity, content_type='application/atom+xml'):
        '''
        Merges an existing entity or inserts a new entity if it does not exist
        in the table. Because this operation can insert or update an entity,
        it is also known as an "upsert" operation.

        table_name: Table name.
        partition_key: PartitionKey of the entity.
        row_key: RowKey of the entity.
        entity:
            Required. The entity object to insert. Could be a dict format or
            entity object.
        content_type: Required. Must be set to application/atom+xml
        '''
        _validate_not_none('table_name', table_name)
        _validate_not_none('partition_key', partition_key)
        _validate_not_none('row_key', row_key)
        _validate_not_none('entity', entity)
        _validate_not_none('content_type', content_type)
        request = HTTPRequest()
        request.method = 'MERGE'
        request.host = self._get_host()
        request.path = '/' + \
            _str(table_name) + '(PartitionKey=\'' + \
            _str(partition_key) + '\',RowKey=\'' + _str(row_key) + '\')'
        request.headers = [('Content-Type', _str_or_none(content_type))]
        request.body = _get_request_body(_convert_entity_to_xml(entity))
        request.path, request.query = _update_request_uri_query_local_storage(
            request, self.use_local_storage)
        request.headers = _update_storage_table_header(request)
        response = self._perform_request(request)

        return _parse_response_for_dict_filter(response, filter=['etag'])

    def _perform_request_worker(self, request):
        auth = _sign_storage_table_request(request,
                                           self.account_name,
                                           self.account_key)
        request.headers.append(('Authorization', auth))
        return self._httpclient.perform_request(request)
