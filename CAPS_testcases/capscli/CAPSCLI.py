#!/usr/bin/python
# encoding: utf-8
#### Libraries
import base64                        # CAPSV HTTP Signature based auth
import httplib as http_client        # Debug logging
import json                          # JSON
import logging                       # Logging config contained in set_debug()
import os.path                       # File existance, file size
import pprint                        # Pretty print for debug
import sys                           # argv handling
from time import gmtime, strftime    # for x-amz-date calculation
import time                          # upload timing
import urllib               # For urlencoding
from xml.etree import ElementTree    # XML handling
from Crypto.Hash import HMAC, SHA256 # [Non-native library] CAPSV HTTP Signature based auth
import requests                      # [Non-native library] HTTP
from prettytable import PrettyTable
#import xlsxwriter
pp = pprint.PrettyPrinter(indent=4, width=1)
import calendar
import time
import re
import datetime
from datetime import datetime as dt
import hashlib
import md5

#from clint.textui import progress

# Globals
version_string = 'Version 1.2.8'
file_limit = 10                # File limit for upload
one_MB = 1024 * 1024            # 1MB constant
# Increased to 32MB based on message capture of CAPSV upload
chunk_size = 32 * one_MB         # Chunk size for MP upload

# Leave this here for now.
# Possible future enhancement: Pull out to config file
# CAPS system information
CAPSV_host = 'https://capsv.nokia.com'
CAPSV_system = {
    'qa' : '/93f6cc8e',
    'production' : '/af8404ca'
    }

# Exit codes
exit_codes = {
    'SUCCESS': 0,
    # Unrecoverable errors
    'INPUT_ERROR': 1,
    'ATTACHMENT_CREATION_FAILURE': 2,
    'SIGNATURE_REJECTED': 3,
    'ATTACHMENT_DELETE_FAILURE': 4,
    'NO_ATTACHMENTS':5,    
    'ATTACHMENT_FETCH_FAILURE':6,
    'TOKEN_REJECTED':7,
    'ATTACHMENT_RESPONSE_MISSING_INFO':8,
    'INTERNAL_ERROR':9,
    'ATTACHMENT_LISTING_FAILURE': 10,
    'ATTACHMENT_RETENTION_FAILURE': 11,
    'ATTACHMENT_CREATION_FAILURE_0': 21,
    'ATTACHMENT_CREATION_FAILURE_1': 22,
    'ATTACHMENT_CREATION_FAILURE_2': 23,
    'TOKEN_ACCESS_RESTRICTION': 24,
    # Possible recoverable errors
    'PATCH_READY_FAILURE': 128,
    'PART_UPLOAD_FAILURE': 129,
    'UPLOAD_COMPLETE_FAILURE': 130,
}

# class: CAPSREST
# This class is used as an interface to CAPS for uploading attachments
#
# Dependancies
#   requests py library: native library for HTTP communications
#
# Instantiation: CAPSREST()
#
#
# Object variables:
#
# Object methods:
#
class CAPSREST(object):

    # Initialize
    def __init__(self, system='production', access_key=None, secret_key=None):

        # CAPSV HTTP signature-based authorization
        self.capsv_access_key = access_key
        self.capsv_secret_key = secret_key
        self.capsv_end_user = 'CAPSCLI'

        self.capsv_url = CAPSV_host+CAPSV_system[system]
        self.capsv_system = CAPSV_system[system]
        self.debug = 0

        # http response varaibles
        self.http_status_code = None
        self.http_status_text = None
        self.http_text = None
        self.http_json = None

        # CAPS lookup dictionaries
        # These map names to ids
        self.customers = {}
        self.customersids = {}
        self.products = {}
        self.classifications = {}

        # Upload attachment metadata
        self.customer_id = None
        self.classification_id = None
        self.product_id = None
        self.productversion_id = None
        self.description = None
        self.purpose = None
        self.retention_days = None
        self.service_class = None
        self.application = None
        self.ticket = None
        self.attachment_files = []# JSON stucture used for CAPSV attachment request
        self.attachment_purpose = []
        self.attachment_ids={}
        self.emaillist = None
        self.datatypecode = None
        '''
        self.files will contain all the information on the files and their upload information

        The keys of files dict will be the filenames. The value of a filename will be a dict:
        files = [
                    {
                        'fqname':'str',    # Filename as given in the input (filename key is basename of fq_filename)
                        'basename':'str',       # Base filename
                        'size':int,             # Size of file
                        'id':#,                 # file id (used by CAPSV)
                        's3keyname':'str',      # s3 keyname for file
                        'upload_id':'str',      # s3 upload id for multipart upload
                        'parts':[
                                    'byte_start':int, # start by of file part
                                    'byte_end':int,   # end byte of file part
                                    'etag':'str'      # Etag for the part
                                ]
                        'etag':'str' # ETag for the completed file (all parts combined)
                    },
                ]
        '''
        self.files = []

        # CAPS/S3 data
        self.capsv_attachment_id = ''
        self.capsv_download_url = ''
        self.capsv_download_url_external = ''
        self.bucket = ''
        self.acl = ''
        self.aws_url = ''
        self.aws_key = ''
        self.signer = ''
        self.user = ''
        self.expiration = ''
        self.permission = ''
        self.signtoken = ''
        self.aws_sig_ver = None
        self.aws_region= None
        self.datetime4= None
        self.canonical_request=None
        # Fiddler debug
        self.fiddler = 0
        self.fiddler_proxies = {}
        self.fiddler_cert = ''

    # Log error data useful for troubleshooting
    def dump_debug(self):
        logging.error('DEBUGGING INFO')
        logging.error('http_status_code:'+str(self.http_status_code))
        logging.error('http_status_text:'+str(self.http_status_text))
        logging.error('http_text:'+str(self.http_text))
        logging.error('http_json:'+str(self.http_json))
        logging.error('/DEBUGGING INFO')

    # Set debug log output
    def set_debug(self, val):
        # If debug is already set to desired value, do nothing
        if self.debug == val:
            return

        if val == 0:
            # Disable debug
            logging.info('[CAPSREST]: Debug logging disabled')
            self.debug = 0
            http_client.HTTPConnection.debuglevel = 0
            logging.getLogger().setLevel(logging.WARNING)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.WARNING)
            requests_log.propagate = False
        else:
            # Enable debug
            self.debug = 1
            http_client.HTTPConnection.debuglevel = 1
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
            logging.info('[CAPSREST]: Debug logging Enabled')

    # Set Fiddler debug settings
    def set_fiddler(self, val, proxies, cert):
        if val == 1:
            # Enable fiddler proxy
            self.fiddler = 1
            self.fiddler_proxies = proxies
            self.fiddler_cert = cert

        else:
            # Disable fiddler proxy
            self.fiddler = 0
            self.fiddler_proxies = {}
            self.fiddler_cert = ''

    # Internal function to fetch self.files[] index based on fq filename
    # This won't scale well but our list of files will always be short so it should not matter
    def get_file_index(self, basename):
        for idx,file_dict in enumerate(self.files):
            #print "in get_file_index",idx,file_dict,self.files
            if file_dict['basename'] == basename:
                return idx
        # Return None if no match is found
        return None            

    # Generate CAPSV HTTP Signature for CAPSV API messages
    # See CAPS Attachment ICD Section 13.4: Http Signature for Browser based client
    def gen_capsv_sig_header(self, request_target):

        # Build authorization signature
        request_target = '(request-target): '+request_target
        amzdate = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())
        thisdate = 'x-amz-date: '+amzdate
        capsenduser = 'x-end-user: '+self.capsv_end_user
        signstring = "%s\n%s\n%s" % (request_target, thisdate, capsenduser)
        secret = self.capsv_secret_key
        hashobj = HMAC.new(secret.encode('utf-8'), digestmod=SHA256)
        hashobj.update(signstring.encode('utf-8'))
        capsv_sig = base64.b64encode(hashobj.digest()).decode("utf-8")
        auth = 'Signature keyId="'+self.capsv_access_key+'",algorithm="hmac-sha256",headers="(request-target) x-amz-date x-end-user",signature="'+capsv_sig+'"'

        # Build HTTP signature authorization header
        capsv_auth_header = {
            'x-amz-date':amzdate,
            'X-End-User':self.capsv_end_user,
            'Content-Type':'application/json',
            'Authorization':auth
        }
        #print"####capsv request_target",request_target
        #print"####capsv header",capsv_auth_header
        # DEBUG
        logging.debug('[gen_capsv_sig_header]request_target:%s', request_target)
        logging.debug('[gen_capsv_sig_header]CAPSV auth header:%s', pp.pformat(capsv_auth_header))

        # Return the header
        return capsv_auth_header

    # Generic http get handler for CAPS API
    def handle_get(self, url, service):
        # Generate HTTP Signature authorization header
        request_target = 'get '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)
        #print "URL and Header at handle get",url,headers
        if self.fiddler == 1:
            # Debug: Fiddler
            try:
                r = requests.get(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500
        else:
            try:
                r = requests.get(url, headers=headers)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500

        # DEBUG
        logging.debug('[handle_get] URL:%s', url)
        logging.debug('[handle_get] Headers:%s', pp.pformat(headers))
        logging.debug('[handle_get] Response Code:%s:%s', str(r.status_code), requests.status_codes._codes[r.status_code][0])
        logging.debug('[handle_get] Response Content-Type:%s', r.headers['content-type'])
        logging.debug('[handle_get] Response test:%s', pp.pformat(r.text))

        # Store HTTP response information in class variables
        self.http_status_code = r.status_code
        self.http_status_text = requests.status_codes._codes[r.status_code][0]
        self.http_text = r.text
        #print "response code in handle get",r.status_code
        # Check for successful response
        if r.status_code == 200:
            # Success: Store json from repsonse
            self.http_json = json.loads(r.text)
            return 0

        # Failure: Clear class json structure
        self.http_status_code = r.status_code
        try:
            self.http_text = r.text
        except:
            self.http_text = "Error Occurred Without Any content or error message from CAPS"
        self.http_json = None            
        return 1

    # Retrieve classification list from CAPSV
    def get_classification_list(self):
        service = '/api/log/classifications'
        url = self.capsv_url+service

        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if ret == 0:
            # Store retrieved list in class variable
            for classification in self.http_json:
                self.classifications.update({classification['name']:classification['id']})
        else:
            # Retrieve failed, clear list
            self.classifications = {}
        return ret

    # Retrieve customer list from CAPSV
    def get_customer_list(self):
        service = '/api/log/customers'
        url = self.capsv_url+service

        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if ret == 0:
            # Store retrieved list in class variable
            #print "getting Customers"
            #print self.http_json
            for customer in self.http_json:
                self.customers.update({customer['name']:customer['id']})

        else:
            # Retrieve failed, clear list
            #print "getting Customers ret not 0"
            self.customers = {}
        return ret

    # Retrieve customer list from CAPSV
    def get_customer_id_list(self):
        service = '/api/log/customers'
        url = self.capsv_url+service

        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if ret == 0:
            # Store retrieved list in class variable
            #print "getting Customers"
            #print self.http_json
            #print type(self.http_json)
            r=0
            #print '\n',len(self.http_json)
            for customer in self.http_json:
                r += 1
                #print r,'\t',customer['id'],customer['country_code']
                self.customersids.update({customer['id_cdb']:customer['country_code']})
        else:
            # Retrieve failed, clear list
            #print "getting Customers ret not 0"
            self.customersids = {}
        return ret

    # Retrieve product list from CAPSV
    def get_product_list(self, customer_id):
        service = '/api/log/customers/'+customer_id+'/producttree'
        url = self.capsv_url+service
        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if ret == 0:
            # Store retrieved list in class variable
            for product in self.http_json:
                self.products.update({product['name']:product['id']})
        else:
            # Retrieve failed, clear list
            self.products = {}
        return ret

    # Retrieve ticket details from CAPSV
    # Results are in self.http_json
    def get_ticket(self, app_name, ticket_id):
        service = '/api/log/ticketdetails/'+app_name+'/'+ticket_id
        url = self.capsv_url+service
        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if (self.debug and ret == 0):
            #print 'DEBUG: JSON returned:'
            pp.pprint(self.http_json)
            return 0
        return ret

    # Retrieve attachment details from CAPSV
    # Test function
    def get_attachments(self, attachment_id):
        service = '/api/log/attachments/'+attachment_id
        url = self.capsv_url+service
        # Send request to CAPSV
        ret = self.handle_get(url, service)
        if ret == 0:
            #print "in new method"
            #pp.pprint(self.http_json)
            logging.info('Attachment fetched get /api/log/attachments/'+attachment_id)     
        else:
            self.dump_debug()
            if self.http_status_code:
                print "Response of Get Attachments /api/log/attachments/"+attachment_id+" Code",self.http_status_code,self.http_text
            logging.error('Failed get /api/log/attachments/'+attachment_id)
            return 1
        return 0

    def get_attachmentreport(self,param,dicval):
        '''This Method takes param as argument which is used to make attachmentreport request url for example 
        'app_name=NCT' and second argument is dicval which is used to return the dictionary containing keys
        as attachment ids and value as this field for that attachmentid
        '''
        attachment_ids_param={}
        service = '/api/log/attachmentreport/attachment?'+param
        url = self.capsv_url+service
        ret = self.handle_get(url, service)
        if ret == 0:
            for file in self.http_json:
                attachment_ids_param.update({file['id']:file[dicval]})
        else:
            self.dump_debug()
            logging.error('Failed get /api/log/attachmentreport/attachment?'+param)
            return 0
        return attachment_ids_param

    # GET Request to API Server with Attachment IDs
    def list_attachment(self, attachment_id):
        service = '/api/log/attachments/'+attachment_id
        url = self.capsv_url+service
        #print "url list attachment",url
        # Generate HTTP Signature authorization header
        request_target = 'get '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)
        #print "header in list attachment",headers

        # Build payload
        payload = None

        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            try:
                r = requests.get(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
            except Exception as e:
                return 500,"ERROR: " +str(e)
        else:
            # No Fiddler
            try:
                r = requests.get(url, headers=headers, json=payload)
            except Exception as e:
                return 500,"ERROR: " +str(e)
        #print "GET RESPONSE CODE",r,r.status_code

        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            #self.http_json = r.json()
            #print self.http_text
            if self.http_status_code == 403 and self.http_text:
                error_str = 'ERROR: '+self.http_text
                logging.error(error_str)
                #print error_str
                return 403,"ERROR:"+error_str
            return r.status_code,"ERROR:"+r.text
        if r.status_code == 200:
            # Success
            #print "Files content",r.json()
            return 200,r

    def downloadfile(self,attachment_id,d_file,size,temppath):
        ##download file
        expire=str(calendar.timegm(time.gmtime())+60)
        oldname=d_file
        d_file=urllib.quote(d_file) 
        if int(self.aws_sig_ver) == 2:
            #print "self.aws_sig_ver is 2" 
            to_sign = 'GET\n\n\n'+expire+'\n/'.encode('utf-8')+self.bucket.encode('utf-8')+'/'.encode('utf-8')+attachment_id.encode('utf-8')+'/'.encode('utf-8')+d_file+'&user='.encode('utf-8')+self.user.encode('utf-8')
            #print "to_sign String is \n",to_sign
            quoted=urllib.quote(to_sign,safe='&,=')
            #print "after quoting \n",quoted
            first='/api/s3sign?expiration='+self.expiration+'&permission='+self.permission+'&signer='+self.signer+'&signtoken='+self.signtoken+'&to_sign='+quoted
            #print "first part",first
            service = first
            url = self.capsv_url+service
            logging.debug("\n url is %r",url)
            #print "url is ",url
            # Generate HTTP Signature authorization header
            request_target = 'get '+self.capsv_system+service
            headers = self.gen_capsv_sig_header(request_target)
            #headers = None
            #print "headers is",headers
            # Build payload
            payload = None
        elif int(self.aws_sig_ver) == 4:
            #print "self.aws_sig_ver is 4",self.aws_sig_ver
            #t=gmtime()
            t=dt.utcnow()
            #t=t+datetime.timedelta(seconds=1)
            #t=t.shift(seconds=+1)
            #t=t.utctimetuple()
            datestamp = t.strftime('%Y%m%d')
            #datestamp = n.strftime('%Y%m%d')
            self.datetime4 = t.strftime('%Y%m%dT%H%M%SZ')
            region = self.aws_region
            service = 's3'
            #print datestamp,region,service
            credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
            credential_scope2 = '/' + datestamp+ '/' + region + '/' + service + '/' + 'aws4_request'
            credential_scope3 = '&X-Amz-Date='+self.datetime4+'&X-Amz-Expires=3600&X-Amz-SignedHeaders=host'
            canonical_uri = '/'+self.bucket+'/'+attachment_id.encode('utf-8')+'/'+d_file
            canonical_querystring = 'X-Amz-Algorithm='+'AWS4-HMAC-SHA256'+'&X-Amz-Credential='+self.aws_key+urllib.quote(credential_scope2,safe='')+credential_scope3
            canonical_headers = 'host:'+self.host+'\n'+'\n'+'host'+'\n'+ 'UNSIGNED-PAYLOAD'
            canonical_request = 'GET' + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers
            self.canonical_request=urllib.quote(canonical_request,safe=':')
            to_sign = 'AWS4-HMAC-SHA256' + '\n' +  self.datetime4 + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
            #print "before quoting \n", to_sign
            quoted=urllib.quote(to_sign,safe='&,=')
            #print "after quoting \n",quoted
            service='/api/s3signv4?canonical_request='+self.canonical_request+'&datetime='+self.datetime4+'&expiration='+self.expiration+'&permission='+self.permission+'&signer='+self.signer+'&signtoken='+self.signtoken+'&to_sign='+quoted+'&user='+self.user.encode('utf-8')
            s3keyname4=self.s3keyname.encode('utf-8')
            quoted_credential_scope=urllib.quote('/'+credential_scope,safe='_,-')
            s3resource = '/'+self.bucket+'/'+s3keyname4+'?X-Amz-Algorithm='+'AWS4-HMAC-SHA256'+'&X-Amz-Credential='+self.aws_key+quoted_credential_scope+'&X-Amz-Date='+self.datetime4+'&X-Amz-Expires=3600&X-Amz-SignedHeaders=host'+'&X-Amz-Signature='
            #print "capsv_url",self.capsv_url
            #print "first part",service
            url = self.capsv_url+service
            logging.debug("\n url is %r",url)
            #print "url is ",url
            # Generate HTTP Signature authorization header
            request_target = 'get '+self.capsv_system+service
            headers = self.gen_capsv_sig_header(request_target)
            #headers = None
            #print "headers is",headers
            # Build payload
            payload = None
        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            try:
                r = requests.get(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500
        else:
            # No Fiddler
            try:
                r = requests.get(url, headers=headers, json=payload)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500
        #print "GET RESPONSE CODE",r,r.status_code
        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            #self.http_json = r.json()
            #print self.http_text
            if self.http_status_code == 403:
                error_str = 'ERROR: Token rejected. Please get a new token.'
                logging.error(error_str)
                #print error_str
                #return(exit_codes['TOKEN_REJECTED'])
            return 0
        if r.status_code == 200:
            # Success
            #print "Files content type",type(r)
            #print "Files content",r.text
            #https://s3.capsv-espoo.nokia.com/a848be61/gdpr/capsvtest1/963b89c8d235457eaad5704fa0388459/Aansturing_Nokia_117430_CAS-145275-Y2P8.pdf.encrypted.zip?AWSAccessKeyId=K7E68ZMW5N39459QA2GZ&Expires=1538046826&Signature=XwC7v%2Btnz2vA5Qi8Ly6ATXdAD9s%3D
            val = urllib.quote(str(r.text).replace('%7E','~'))
            
            if int(self.aws_sig_ver) == 2:
                downloadurl  = self.aws_url+'/'+self.bucket+'/'+attachment_id+'/'+d_file+'?AWSAccessKeyId='+self.aws_key+'&Expires='+expire+'&Signature='+val
            elif int(self.aws_sig_ver) == 4:
                downloadurl  = self.aws_url+s3resource+val
            logging.debug("\n download url %r",downloadurl)
            # Build header
            #from tqdm import tqdm
            if self.fiddler == 1:
                try:
                    r = requests.get(downloadurl, headers='',stream=True, proxies=self.fiddler_proxies, verify=self.fiddler_cert)
                except Exception as e:
                    print "ERROR: " +str(e)
                    return 500
            else:
                try:
                    r = requests.get(downloadurl, headers='',stream=True)
                except Exception as e:
                    print "ERROR: " +str(e)
                    return 500
            if r.status_code == 200:
                #print r.status_code
                total_size = int(size)
                #block_size = 10
                #wrote = 0 
                download_start = time.time()
                with open(temppath+oldname, "wb") as f:
                    total_length = total_size
                    if total_size is None: # no content length header
                        f.write(r.content)
                    else:
                        dl = 0
                        outprint = ''
                        print('Downloading: {}'.format(oldname))
                        for chunk in r.iter_content(chunk_size=1024):
                            dl += len(chunk)
                            outprint += '='
                            f.write(chunk)
                            done = int(50 * dl / total_length)
                            sys.stdout.write("\r%s%s" % ('=' * done, ' ' * (50-done)) )    
                            sys.stdout.flush()
                        f.close()
                        filesize = os.path.getsize(temppath+oldname)
                        if  filesize >=  total_size:
                            sys.stdout.write("\r%s%s" % ('=' * 100, ' Download Completed' ) )    
                            sys.stdout.flush()
                            print "\n"
                            download_end = time.time()
                            download_dur = max(.01, download_end - download_start)
                            download_rate = (filesize/(1024*1024))/download_dur # MB/s
                            stats_str = '[Size:'+str(filesize)+' bytes; Duration:{0:05.2f}'.format(download_dur)+'s; Rate:{0:05.2f}'.format(download_rate)+'MB/s]'
                            sys.stdout.write('Downloading '+oldname+': Complete. '+stats_str+'\n')
                            sys.stdout.flush()
                        else:
                            sys.stdout.write("\r%s%s" % ('=' * done, ' Download Not Done Completely' ) )    
                            sys.stdout.flush()
                            print "\n"
                return r.status_code
            else:
                print "download request not success response code , ",r.status_code
                return r.status_code
        else:
            return 0

    # GET Request to API Server with Attachment IDs
    def dl_attachment(self,attachment_id,d_file,dlpath):
        #print "calling get_attachments for",attachment_id
        ret=self.get_attachments(attachment_id)
        #print "response of get_attachments",ret
        if ret==0:
            if self.http_json:              
                #print "response of http_json",self.http_json
                #for r_json in self.http_json:
                r_json = self.http_json
                try:
                    if (r_json['evaporate'] == None):
                        logging.error('[dl_attachment] This token is not authorized for downloads.')
                        print "This token is not authorized for downloads."
                        sys.exit(exit_codes['TOKEN_ACCESS_RESTRICTION'])
                    self.bucket = r_json['evaporate']['bucket']
                    self.acl = r_json['evaporate']['acl']
                    self.capsv_attachment_id = r_json['id']
                    self.aws_url = r_json['evaporate']['aws_url']
                    self.aws_key = r_json['evaporate']['aws_key']
                    self.size= r_json['evaporate']['part_size']
                    self.signer = r_json['evaporate']['sign_params']['signer']
                    self.user = r_json['evaporate']['sign_params']['user']
                    self.expiration = r_json['evaporate']['sign_params']['expiration']
                    #print "\n \nEXPIRATION",self.expiration
                    self.expiration=str(self.expiration)
                    self.permission = r_json['evaporate']['sign_params']['permission']
                    self.signtoken = r_json['evaporate']['sign_params']['signtoken']
                    #print"r_json['files']",r_json['files']
                    self.files=r_json['files']
                    self.retentiondaysleft=r_json['retentiondaysleft']
                    self.decryption=r_json['encryption_key']
                    self.aws_sig_ver= r_json['evaporate']['aws_signature_version']
                    self.aws_region= r_json['evaporate']['s3_region']
                    self.host= self.aws_url.split('/')[2]
                    if self.retentiondaysleft == 0:
                        print "This attachment Can not be Downloaded as its Expired (retention value is 0)"
                        sys.exit(exit_codes['ATTACHMENT_RETENTION_FAILURE'])#return 0
                    else:
                        print "Total Downloadable Files (Which are in Status ready)",len([i for i in r_json['files'] if (i['status']=='ready' and i['type'] not in ('original', 'scrambledmetrics', 'scrambledlog'))])
                        if len([i for i in r_json['files'] if (i['status']=='ready' and i['type'] not in ('original', 'scrambledmetrics', 'scrambledlog'))]) == 0:
                            print "No files Present which can be downloaded" 
                            sys.exit(exit_codes['ATTACHMENT_LISTING_FAILURE'])
                        retarray=[]
                        notfound=True
                        print "\nDecryption Key for this Attachment is",self.decryption
                        for file_json in [i for i in r_json['files'] if (i['status']=='ready' and i['type'] not in ('original', 'scrambledmetrics', 'scrambledlog'))]:
                            basename  = file_json['name'].encode('utf-8')
                            #file_idx = self.get_file_index(basename)
                            file_idx = basename
                            #print "file_idx is ",file_idx
                            if (file_idx == None):
                                error_str = '[dl_attachment] ERROR: unexpected filename: '+basename
                                logging.error(error_str)
                                print error_str
                                return(exit_codes['INTERNAL_ERROR'])
                            size=file_json['size']
                            ##TODO :Handle in case of all of list of files
                            #print "d_file is ",d_file
                            if d_file != " ":
                                #print "In d_file check ",d_file
                                if (file_idx == d_file):
                                    self.s3keyname = file_json['s3keyname']
                                    #print "downloading file",d_file
                                    ret=self.downloadfile(attachment_id,d_file,size,dlpath)
                                    notfound=False
                                    return ret 
                            else:
                                #print "downloading file_iteration",file_idx
                                self.s3keyname = file_json['s3keyname']
                                ret=self.downloadfile(attachment_id,file_idx,size,dlpath)
                                retarray.append(ret)
                        if d_file == " ":
                            return retarray
                        else:
                            if notfound:
                                print "File not found",d_file 
                                return 0
                except KeyError as error:
                    logging.error('[dl_attachment] json response missing information. Captured error: '+str(error))
                    print"[dl_attachment] json response missing information. Captured error: ',str(error)"
                    sys.exit(exit_codes['ATTACHMENT_RESPONSE_MISSING_INFO'])
                    
            else:
                print  "Get Attachments failed , self.https_json is null",self.http_json
                logging.error('[dl_attachment] json response is null')
                return 0
        else:
            logging.error('[dl_attachment] Get Attachments failed')  
            return 0
    

    # Set attachment retension time to 0
    def delete_attachment(self, attachment_id):
        service = '/api/log/attachments/'+attachment_id
        url = self.capsv_url+service

        # Generate HTTP Signature authorization header
        request_target = 'patch '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)

        # Build payload
        payload = {
            'retention_days':0
        }

        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            try:
                r = requests.patch(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500
        else:
            # No Fiddler
            try:
                r = requests.patch(url, headers=headers, json=payload)
            except Exception as e:
                print "ERROR: " +str(e)
                return 500
        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return 1

        # Success
        return 0

    # CAPSV: S3 message signer
    def sign_msg(self, to_sign):
        # Generate HTTP Signature authorization header
        if int(self.aws_sig_ver)== 2:
            service = '/api/s3sign'
            url = self.capsv_url+service
            request_target = 'get '+self.capsv_system+service
            # params
            params = {
                'to_sign':to_sign,
                'signer':self.signer,
                'user':self.user,
                'expiration':self.expiration,
                'permission':self.permission,
                'signtoken':self.signtoken
            }
            headers = self.gen_capsv_sig_header(request_target)
        elif int(self.aws_sig_ver)== 4 :
            service = '/api/s3signv4'
            url = self.capsv_url+service
            request_target = 'get '+self.capsv_system+service
            params = {
                'to_sign':to_sign,
                'datetime':self.datetime4,
                'canonical_request':self.canonical_request,
                'signer':self.signer,
                'user':self.user,
                'expiration':self.expiration,
                'permission':self.permission,
                'signtoken':self.signtoken
            }
            headers = self.gen_capsv_sig_header(request_target)

        # We need to manually URL encode the individual parameters because the requires library was URL encoding
        # spaces in the to_sign string as + instead of %20 which caused signing to fail. It did this because this
        # string appears after the 's3sign?' in the built URL.
        params_list = []
        for key in params.keys():
            # The replace calls are a horrible hack to deal with ~ in filenames. TODO: Investigate handling of this.
            val = urllib.quote(str(params[key]).replace('%7E','~'),safe='')
            params_list = params_list + [key+'='+val]

        params_str = '&'.join(params_list)
        #print "DEBUG:params_str:"+params_str

        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.get(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, params=params_str)

        else:
            # setting params to string keeps requests from further URLEncoding the string.
            #print "url inside sign \n",url,headers,params_str
            #print "headers inside sign \n",headers
            #print "params inside sign \n",params_str

            r = requests.get(url, headers=headers, params=params_str)

        if r.status_code != 200:
            # Failure in return
            #print "r.status_code inside sign_msg",r.status_code
            #print("r.body inside sign_msg",r.request.body)
            #print("r.headers",r.request.headers)
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return ''

        #Success. Return signature
        #print "in S3.sign r.text val is ",r.text
        return r.text

    def sign_msg_get(self, to_sign):

        service = '/api/s3sign'
        url = self.capsv_url+service

        # Generate HTTP Signature authorization header
        request_target = 'get '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)

        #print "DEBUG:tosign:"+to_sign
        # params
        params = {
            'to_sign':to_sign,
            'user':self.user,
        }

        # We need to manually URL encode the individual parameters because the requires library was URL encoding
        # spaces in the to_sign string as + instead of %20 which caused signing to fail. It did this because this
        # string appears after the 's3sign?' in the built URL.
        params_list = []
        for key in params.keys():
            # The replace calls are a horrible hack to deal with ~ in filenames. TODO: Investigate handling of this.
            val = urllib.quote(str(params[key]).replace('%7E','~'))
            params_list = params_list + [key+'='+val]

        params_str = '&'.join(params_list)
        #print "DEBUG:params_str:"+params_str

        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.get(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, params=params_str)

        else:
            # setting params to string keeps requests from further URLEncoding the string.
            #print "url inside sign",url,headers,params_str
            r = requests.get(url, headers=headers, params=params_str)

        if r.status_code != 200:
            # Failure in return
            #print "r.status_code inside sign_msg",r.status_code
            #print("r.body inside sign_msg",r.request.body)
            #print("r.headers",r.request.headers)
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return ''

        # Success. Return signature
        #print "in S3.sign r.text val is ",r.text
        return r.text

    # Load attachment metadata into class
    def prepare_attachment(self, **kwargs):
        logging.info('[prepare_attachment] Called with '+str(kwargs))
        self.customer_id = kwargs.get('customer')
        self.classification_id = kwargs.get('classification')
        self.product_id = kwargs.get('product')
        self.productversion_id = kwargs.get('productrel')
        self.description = kwargs.get('description')
        self.purpose = kwargs.get('purpose')
        self.application = kwargs.get('ticketapp')
        self.retention_days = kwargs.get('retention')
        self.service_class = kwargs.get('service')
        self.ticket = kwargs.get('ticket')
        self.emaillist = kwargs.get('emaillist')
        self.datatypecode = kwargs.get('datatypecode')

        files = kwargs.get('files')

        # Process list of files to be uploaded
        for filename in files:
            # Verify file exists
            if os.path.isfile(filename) != 1:
                # File not found
                logging.error('[prepare_attachment]ERROR Unable to find file '+filename)
                return 1
            filesize = os.path.getsize(filename)

            # Save file information in our class' file dict
            file_basename = os.path.basename(filename)
            self.files.append({'basename':file_basename, 'fqname':filename, 'size':filesize})

            # Create structure used for CAPSV attachment request (no need to build it later)
            # Only use file basename in this structure
            self.attachment_files.append({'name':file_basename, 'size':filesize})
        #print "Attachment_files",str(self.attachment_files)
        logging.info('[prepare_attachment] Attachment_files, %s', str(self.attachment_files))
        return 0

    def prepare_attachment_light(self, **kwargs):
        logging.info('[prepare_attachment] Called with '+str(kwargs))
        self.files=[]
        self.customer_id = kwargs.get('customer')
        self.classification_id = kwargs.get('classification')
        self.product_id = kwargs.get('product')
        self.productversion_id = kwargs.get('productrel')
        self.description = kwargs.get('description')
        self.purpose = kwargs.get('purpose')
        self.application = kwargs.get('ticketapp')
        self.retention_days = kwargs.get('retention')
        self.service_class = kwargs.get('service')
        self.ticket = kwargs.get('ticket')
        self.emaillist = kwargs.get('emaillist')
        self.datatypecode = kwargs.get('datatypecode')
        filename = kwargs.get('files')
        if os.path.isfile(filename) != 1:
           # File not found
           logging.error('[prepare_attachment]ERROR Unable to find file '+filename)
           return 1
        file_basename = os.path.basename(filename)
        filesize = os.path.getsize(filename)
        self.attachment_files =[]
        self.files.append({'basename':file_basename, 'fqname':filename, 'size':filesize})
        self.attachment_files.append({'name':file_basename, 'size':filesize})
        #print "Attachment_files",str(self.attachment_files)
        logging.info('[prepare_attachment] Attachment_files, %s', str(self.attachment_files))
        return 0

    # CAPSV: Create attachment
    def create_attachment(self):
        service = '/api/log/attachments'
        url = self.capsv_url + service

        # Generate HTTP Signature authorization header
        request_target = 'post '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)

        # Build payload
        payload = {
            'app':'CAPSCLI',
            'customer':{'id_cdb':self.customer_id},
            'product':{'id_cdb':self.product_id},
            'classification':{'id':self.classification_id},
            'description':self.description,
            'purpose':self.purpose,
            'retention_days':self.retention_days,
            'service_class':self.service_class,
            'files':self.attachment_files
          }
		 
        if self.emaillist != None:
            payload['emaillist'] = self.emaillist
        
        if self.datatypecode != None:
            payload['datatypecode'] = self.datatypecode

        # Add optional parameters

        # Only use product version, if it's defined. Otherwise use product
        # We expect the caller to verify one of these are populated
        if self.productversion_id != None:
            payload['productversion'] = {'id_cdb':self.productversion_id}

        if (self.ticket != None and self.application != None):
            #print "Ticket and application are not none",self.ticket,self.application
            payload['ticket'] = {'app_name':self.application, 'ticket_id':self.ticket}
        elif (self.ticket == None and self.application == "REFRA"):
            # Allow REFRA app to send without ticket id (CAPS-1018)
            # print "DEBUG: Empty ticket# for REFRA",self.ticket,self.application
            payload['ticket'] = {'app_name':self.application, 'ticket_id':None}
        #print "Payload",payload 
        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.post(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
        else:
            # No Fiddler
            r = requests.post(url, headers=headers, json=payload)

        # Check for successful response
        if r.status_code != 201:
            # Error
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            if r.text:
                self.http_text = r.text
                try:
                    self.http_json = json.loads(r.text)
                except:
                    print "create_attachment Got failed though response was success but r.text not having json data",r.status_code,payload
                    return(exit_codes['ATTACHMENT_CREATION_FAILURE_1'])  
            else:
                print "create_attachment Got failed though response was success but r.text not present",r.status_code,payload
                return(exit_codes['ATTACHMENT_CREATION_FAILURE_1'])  
            if r.status_code == 403:
                error_str = 'ERROR: Token rejected. Please get a new token.'
                logging.error(error_str)
                print error_str
                return(exit_codes['TOKEN_REJECTED'])
            elif r.status_code == 400:
                error_str = 'ERROR: CAPSV reported bad request. See log for additional information.'
                print error_str
                logging.error(error_str)
                logging.error("payload: %s", payload)

                # Try to handle specific error
                #print ("message: %s" % self.http_json['error']['message'])
                pattern = 'ValidationError: \[u\'([^\']+)'
                match = re.search(pattern, self.http_json['error']['message'])
                if match:
                    print match.group(1), '\n'
                
                pattern = 'is not valid'
                match = re.search(pattern, self.http_json['error']['message'])
                if match:
                    print ("Invalid parameter: %s" % self.http_json['error']['message'])

                return(exit_codes['ATTACHMENT_CREATION_FAILURE_0'])
            else:
                # Catch-all error
                error_str = 'ERROR: CAPSV rejected request. See log for additional information.'
                print error_str
                logging.error(error_str)
                logging.error("payload: %s", payload)
                return(exit_codes['ATTACHMENT_CREATION_FAILURE_0'])

        # Success
        # Load json resonse into structure
        if r.json():
            r_json = r.json()
        else:
            print "create_attachment Got failed though response was success but response.json() not having data",r.status_code,payload
            return(exit_codes['ATTACHMENT_CREATION_FAILURE_2'])                

        # DEBUG print
        #print "CREATE ATTACHMENT_CREATION r_json",r_json

        # json data of interest
        try:
            self.bucket = r_json['evaporate']['bucket']
            self.acl = r_json['evaporate']['acl']
            self.capsv_attachment_id = r_json['id']
            self.capsv_download_url = r_json['download_url']
            self.capsv_download_url_external = r_json['download_url_external']
            self.aws_url = r_json['evaporate']['aws_url']
            self.aws_key = r_json['evaporate']['aws_key']
            self.signer = r_json['evaporate']['sign_params']['signer']
            self.user = r_json['evaporate']['sign_params']['user']
            self.expiration = r_json['evaporate']['sign_params']['expiration']
            self.permission = r_json['evaporate']['sign_params']['permission']
            self.signtoken = r_json['evaporate']['sign_params']['signtoken']
            self.aws_sig_ver= r_json['evaporate']['aws_signature_version']
            self.aws_region= r_json['evaporate']['s3_region']
            self.host= self.aws_url.split('/')[2]
        except KeyError as error:
            logging.error('[create_attachment] json response missing information. Captured error: '+str(error))
            return(exit_codes['ATTACHMENT_RESPONSE_MISSING_INFO'])

        for file_json in r_json['files']:
            basename  = file_json['name'].encode('utf-8')
            #print "basename",basename
            #print "self.files",self.files

            file_idx = self.get_file_index(basename)
            #print "file_idx",file_idx            
            if (file_idx == None):
                error_str = '[create_attachment] ERROR: unexpected filename: '+basename
                logging.error(error_str)
                print error_str
                return(exit_codes['INTERNAL_ERROR'])

            self.files[file_idx]['id'] = file_json['id']
            self.files[file_idx]['s3keyname'] = file_json['s3keyname']

        logging.debug('[create_attachment] json:%s', pp.pformat(json.loads(r.text)))
        logging.info('[create_attachment] Attachment created: '+self.capsv_attachment_id)
        return 0

    # S3:Multipart init
    def s3_mp_upload_init(self, basename):
        logging.info('[s3_mp_upload_init] Initializing multipart upload for '+basename)
        file_idx = self.get_file_index(basename)
        if (file_idx == None):
            error_str = '[s3_mp_upload_init] ERROR: missing information for filename: '+basename
            logging.error('[s3_mp_upload_init] ERROR: missing information for filename: %s',error_str)
            return(exit_codes['INTERNAL_ERROR'])
        
        s3keyname = self.files[file_idx]['s3keyname']
        s3keyname_uenc = urllib.quote(s3keyname.encode('utf-8'), safe='')
        if int(self.aws_sig_ver)==2:
            # Call signer
            amzdate = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())
            to_sign = 'POST\n\n\n\n'+'x-amz-acl:'+self.acl+'\n'+'x-amz-date:'+amzdate+'\n'+'/'+self.bucket+'/'+s3keyname_uenc+'?uploads'
            msg_sign_str = self.sign_msg(to_sign)
            if msg_sign_str == '':
                # signature failed
                #print "signature failed"
                return exit_codes['SIGNATURE_REJECTED']
            s3auth = self.aws_key+':'+msg_sign_str
            headers = {
            'Authorization': 'AWS '+s3auth,
            'x-amz-acl':self.acl,
            'x-amz-date':amzdate,
            }
        elif int(self.aws_sig_ver)== 4:
            #print "self.aws_sig_ver is 4"
            algorithm = 'AWS4-HMAC-SHA256'
            t=gmtime()
            datestamp = strftime('%Y%m%d',t)
            amzdate = strftime('%Y%m%dT%H%M%SZ',t)
            self.datetime4 = amzdate
            region = self.aws_region
            service = 's3'
            credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
            #canonincal_request
            method = 'POST'
            bucket = self.bucket
            s3keyname4 =s3keyname_uenc
            canonical_uri = '/'+self.aws_url.split('/')[3]+'/'+self.aws_url.split('/')[4]+'/'+bucket+'/'+s3keyname4
            canonical_querystring = 'uploads='
            host=self.host
            canonical_headers = 'host:' + host + '\n' +'x-amz-acl:' +'private'+'\n'+ 'x-amz-date:' + amzdate +'\n'
            signed_headers = 'host;x-amz-acl;x-amz-date'
            # This message has no payload so payload hash is ''
            payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
            self.canonical_request=canonical_request
            to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
            #print to_sign
            #print "payload_hash",payload_hash
            #See canonical_request below
            msg_sign_str = self.sign_msg(to_sign)
            if msg_sign_str == '':
                # signature failed
                print "signature failed"
                return exit_codes['SIGNATURE_REJECTED']
            #s3auth = self.aws_key+':'+msg_sign_str
            s3auth = "Credential="+self.aws_key+"/"+credential_scope+", SignedHeaders="+signed_headers+", Signature="+msg_sign_str
            headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '+s3auth,
            'x-amz-acl':self.acl,
            'x-amz-date':amzdate,
            'x-amz-content-sha256': payload_hash
            }

        # Build multipart init
        url = self.aws_url+'/'+self.bucket+'/'+s3keyname_uenc+'?uploads'
        #print "url is",url
        # Build header
        #print headers
        # Send request to S3
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.post(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert)
        else:
            r = requests.post(url, headers=headers)

        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return 1

        # Success
        # Extract UploadId from mp init response
        tree = ElementTree.fromstring(r.content)
        namespace = tree.tag[1:].split("}")[0]
        self.files[file_idx]['upload_id'] = tree.find('.//{%s}UploadId' % namespace).text
        self.files[file_idx]['parts'] = [] # Prepare parts array
        return 0

    # S3:Multipart upload file
    # This function will handle all of the s3 messaging for a file upload:
    #   s3_mp_upload_init
    #   chunking and individual part upload calls (s3_upload_part)
    #   s3_mp_upload_complete
    def s3_mp_upload_file(self, filename):
        logging.info('[s3_mp_upload_file] Preparing upload for '+filename)
        basename = os.path.basename(filename)

        file_idx = self.get_file_index(basename)
        if (file_idx == None):
            error_str = '[s3_mp_upload_file] ERROR: missing information for filename: '+basename
            logging.error('[s3_mp_upload_file] ERROR: missing information for filename: %s',error_str)
            return(exit_codes['INTERNAL_ERROR'])
        
        # Start mutipart upload init
        ret = self.s3_mp_upload_init(basename)
        if ret > 0:
            # Error
            return ret


        upload_id = self.files[file_idx]['upload_id']
        s3keyname = self.files[file_idx]['s3keyname']
        logging.info('[s3_mp_upload_file] Upload started for '+upload_id+s3keyname)

        # Open filehandle
        f_in = open(filename, 'rb')

        # Break file into chunks
        filesize = os.path.getsize(filename)
        part_number = 1
        sys.stdout.write('Uploading '+filename+': 00.00%\r')
        sys.stdout.flush()
        transferred_data = 0
        logging.info('[s3_mp_upload_file] Upload started for '+filename)
        upload_start = time.time()
        for data in iter(lambda: f_in.read(chunk_size), ''):

            # TODO: Need to track byte start/end for part retry?
            self.files[file_idx]['parts'].append({'etag':None})

            # Call s3 upload part to upload the chunk
            ret = self.s3_upload_part(basename, part_number, data)
            part_number += 1

            # If we encounter an error, stop the loop
            if ret > 0:
                f_in.close()
                # print newline to end progress prints from above
                sys.stdout.write('Uploading '+filename+': Error!\n')
                print ''
                return ret
            else:
                # Print out progress indicator. Use float typecast to trigger float division (otherwise result is integer)
                # Use \r character to return to start of line so next progress indicator overwrites previous one.
                # This gives the illusion of an inline update to the output
                transferred_data += len(data)
                progress = (transferred_data*100)/float(filesize)
                sys.stdout.write('Uploading '+str(filename)+': {0:05.2f}%\r'.format(progress))
                sys.stdout.flush()

        upload_end = time.time()
        upload_dur = max(.01,upload_end - upload_start)
        upload_rate = (filesize/(1024*1024))/upload_dur # MB/s

        stats_str = '[Size:'+str(filesize)+' bytes; Duration:{0:05.2f}'.format(upload_dur)+'s; Rate:{0:05.2f}'.format(upload_rate)+'MB/s]'
        logging.info('[s3_mp_upload_file] Upload completed for '+filename+'. '+stats_str)
        sys.stdout.write('Uploading '+filename+': Complete. '+stats_str+'\n')
        sys.stdout.flush()

        # Close filehandle
        f_in.close()

        # Send upload complete
        ret = self.s3_mp_upload_complete(basename,filename)
        #print ret
        if ret > 0:
            return ret

        return 0

    # S3:Multipart part upload
    def s3_upload_part(self, basename, part_number, data):
        file_idx = self.get_file_index(basename)
        if (file_idx == None):
            error_str = '[s3_upload_part] ERROR: missing information for filename: '+basename
            logging.error('[s3_upload_part] ERROR: missing information for filename: %s',error_str)
            return(exit_codes['INTERNAL_ERROR'])

        # Put together information for URL and signer
        upload_id = self.files[file_idx]['upload_id']
        s3keyname = self.files[file_idx]['s3keyname']
        s3keyname_uenc = urllib.quote(s3keyname.encode('utf-8'), safe='')

        amzdate = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())

        # Build URL
        url = self.aws_url+'/'+self.bucket+'/'+s3keyname_uenc+'?partNumber='+str(part_number)+'&uploadId='+upload_id
        if int(self.aws_sig_ver)==2:
            # Build message to sign
            to_sign = 'PUT\n\n\n\n'+'x-amz-date:'+amzdate+'\n'+'/'+self.bucket+'/'+s3keyname_uenc+'?partNumber='+str(part_number)+'&uploadId='+upload_id
            # Call CAPSV signer
            msg_sign_str = self.sign_msg(to_sign)
            if msg_sign_str == '':
                # signature failed
                return exit_codes['SIGNATURE_REJECTED']
            s3auth = self.aws_key+':'+msg_sign_str
            # Build header
            headers = {
                'Authorization': 'AWS '+s3auth,
                'x-amz-date':amzdate,
                }
        elif int(self.aws_sig_ver)== 4:
            #print "self.aws_sig_ver is 4"
            algorithm = 'AWS4-HMAC-SHA256'
            t=gmtime()
            datestamp = strftime('%Y%m%d',t)
            amzdate = strftime('%Y%m%dT%H%M%SZ',t)
            self.datetime4 = amzdate
            region = self.aws_region
            service = 's3'
            credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
            #canonincal_request
            method = 'PUT'
            bucket = self.bucket
            s3keyname4 =s3keyname_uenc
            canonical_uri = '/'+self.aws_url.split('/')[3]+'/'+self.aws_url.split('/')[4]+'/'+bucket+'/'+s3keyname4
            canonical_part = 'partNumber='+str(part_number)+'&uploadId='+upload_id
            canonical_querystring = 'uploads='
            host=self.host
            canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate 
            sign_headers = 'content-md5;host;x-amz-date'
            #to-do below
            #md5data = hashlib.md5(data.encode('base64')).hexdigest()
            md5data = base64.b64encode(hashlib.md5(data).digest())
            #print md5data
            canonical_part2 = 'content-md5:'+md5data
            # This message has no payload so payload hash is ''
            payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_part + '\n' + canonical_part2 + '\n' + canonical_headers + '\n'+'\n'+sign_headers + '\n' + 'UNSIGNED-PAYLOAD'
            #canonical_request = method + '\n' + canonical_uri + '\n' + canonical_part + '\n' + canonical_headers + '\n'+'\n'+sign_headers + '\n' + 'UNSIGNED-PAYLOAD'
            self.canonical_request=canonical_request
            to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
            #print to_sign
            # Call CAPSV signer
            msg_sign_str = self.sign_msg(to_sign)
            #print "msg_sign_str",msg_sign_str
            if msg_sign_str == '':
                # signature failed
                return exit_codes['SIGNATURE_REJECTED']
            #s3auth = self.aws_key+':'+msg_sign_str
            s3auth = "Credential="+self.aws_key+"/"+credential_scope+", SignedHeaders="+sign_headers+", Signature="+msg_sign_str

            #Build header
            headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '+s3auth,
            'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
            'x-amz-date':amzdate,
            'content-md5':md5data,
            }

        # Send request to S3
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.put(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, data=data)
        else:
            r = requests.put(url, headers=headers, data=data)

        if r.status_code != 200:
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return exit_codes['PART_UPLOAD_FAILURE']

        index = part_number-1
        self.files[file_idx]['parts'][index]['etag'] = r.headers.get('ETag')
        return 0

    # S3:Multipart upload complete
    def s3_mp_upload_complete(self, basename,filename):
        logging.info('[s3_mp_upload_complete] Completing multipart upload')

        file_idx = self.get_file_index(basename)
        if (file_idx == None):
            error_str = '[s3_mp_upload_complete] ERROR: missing information for filename: '+basename
            logging.error('[s3_mp_upload_complete] ERROR: missing information for filename: %s',error_str)     
            return(exit_codes['INTERNAL_ERROR'])
        
        # Put together information for URL and signer
        upload_id = self.files[file_idx]['upload_id']
        s3keyname = self.files[file_idx]['s3keyname']
        s3keyname_uenc = urllib.quote(s3keyname.encode('utf-8'), safe='')

        amzdate = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime())

        # Build URL
        url = self.aws_url+'/'+self.bucket+'/'+s3keyname_uenc+'?uploadId='+upload_id
        # Use XML lib to form body, list of file parts and their etags
        # Example:
        # <CompleteMultipartUpload>
        #   <Part>
        #       <PartNumber>1</PartNumber>
        #       <ETag>74d452edd5ce583ed6d8e279d75e0c12</ETag>
        #   </Part>
        #   <Part>
        #       <PartNumber>2</PartNumber>
        #       <ETag>437c24c14d92ba0f04b0b69d564c4145</ETag>
        #   </Part>
        #</CompleteMultipartUpload>'
        root_xml = ElementTree.Element('CompleteMultipartUpload')
        index = 0
        for part in self.files[file_idx]['parts']:
            part_xml = ElementTree.SubElement(root_xml, 'Part')
            partNumber_xml = ElementTree.SubElement(part_xml, 'PartNumber')
            partNumber_xml.text = str(index+1)
            etag_xml = ElementTree.SubElement(part_xml, 'ETag')
            etag_xml.text = self.files[file_idx]['parts'][index]['etag']
            index += 1
        body = ElementTree.tostring(root_xml)
        if int(self.aws_sig_ver)== 2:
        # Build message to sign
            to_sign = 'POST\n\napplication/xml; charset=UTF-8\n\n'+'x-amz-date:'+amzdate+'\n'+'/'+self.bucket+'/'+s3keyname_uenc+'?uploadId='+upload_id
            # Call CAPSV signer
            msg_sign_str = self.sign_msg(to_sign)
            if msg_sign_str == '':
                # signature failed
                return exit_codes['SIGNATURE_REJECTED']
            s3auth = self.aws_key+':'+msg_sign_str
            # Build header
            headers = {
                'Authorization': 'AWS '+s3auth,
                'Content-Type':'application/xml; charset=UTF-8',
                'x-amz-date':amzdate,
                }
        elif int(self.aws_sig_ver)== 4:
            #print "self.aws_sig_ver is 4"
            algorithm = 'AWS4-HMAC-SHA256'
            t=gmtime()
            datestamp = strftime('%Y%m%d',t)
            amzdate = strftime('%Y%m%dT%H%M%SZ',t)
            self.datetime4 = amzdate
            region = self.aws_region
            service = 's3'
            credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
            #canonincal_request
            method = 'POST'
            bucket = self.bucket
            s3keyname4 =s3keyname_uenc
            canonical_uri = '/'+self.aws_url.split('/')[3]+'/'+self.aws_url.split('/')[4]+'/'+bucket+'/'+s3keyname4
            canonical_part = 'uploadId='+upload_id
            canonical_querystring = 'uploads='
            host=self.host
            canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate 
            sign_headers = 'content-type;host;x-amz-date'
            payload_hash = hashlib.sha256((body).encode('utf-8')).hexdigest()
            #payload_hash="c7380fc1a1cee0b449c5d39c09586a3746c7bb225978f3bf0eb427a709cafda4"
            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_part + '\n' + canonical_headers + '\n' + '\n' + sign_headers + '\n' + payload_hash
            self.canonical_request=canonical_request
            to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
            # Call CAPSV signer
            msg_sign_str = self.sign_msg(to_sign)
            if msg_sign_str == '':
                # signature failed
                return exit_codes['SIGNATURE_REJECTED']
            s3auth = "Credential="+self.aws_key+"/"+credential_scope+", SignedHeaders="+sign_headers+", Signature="+msg_sign_str
            #Build header
            headers = {
            'Authorization': 'AWS4-HMAC-SHA256 '+s3auth,
            'x-amz-content-sha256': payload_hash,
            'x-amz-date':amzdate,
            }
        # Send request to S3
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.post(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, data=body)
        else:
            r = requests.post(url, headers=headers, data=body)

        # TODO: extract and store final file etag (do we need it?)

        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return exit_codes['UPLOAD_COMPLETE_FAILURE']

        # Success
        return 0
        
    # CAPSV:PATCH status to ready
    def capsv_update_attachment_params(self,attachement_id,val,description,purpose):
        service = '/api/log/attachments/'+attachement_id
        url = self.capsv_url+service

        # Generate HTTP Signature authorization header
        request_target = 'patch '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)

        # TODO: Improve this to handle partial upload failure
        # Build payload with file list
        payload = {
            'id':attachement_id,
            'retention_days':val,
            'description':description,
            'purpose':purpose
            }

        #print"DEBUG: inside capsv_update_attachment_params payload",payload
        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.patch(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
        else:
            # No Fiddler
            r = requests.patch(url, headers=headers, json=payload)
        #print"DEBUG: inside capsv_send_ready r",r,r.json()
        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return 1

        # Success
        return 0
        
    # CAPSV:PATCH status to ready
    def capsv_send_ready(self):
        service = '/api/log/attachments/'+self.capsv_attachment_id
        url = self.capsv_url+service

        # Generate HTTP Signature authorization header
        request_target = 'patch '+self.capsv_system+service
        headers = self.gen_capsv_sig_header(request_target)

        # TODO: Improve this to handle partial upload failure
        # Build payload with file list
        files = []
        for file_dict in self.files:
            files.append({'id':file_dict['id'], 'status':'ready'})
           
        payload = {
            'files':files
            }
        #print"DEBUG: inside capsv_send_ready payload",payload
        # Send request to CAPSV
        if self.fiddler == 1:
            # Debug: Fiddler
            r = requests.patch(url, headers=headers, proxies=self.fiddler_proxies, verify=self.fiddler_cert, json=payload)
        else:
            # No Fiddler
            r = requests.patch(url, headers=headers, json=payload)
        #print"DEBUG: inside capsv_send_ready r",r,r.json()
        if r.status_code != 200:
            # Failure
            self.http_status_code = r.status_code
            self.http_status_text = requests.status_codes._codes[r.status_code][0]
            self.http_text = r.text
            return 1

        # Success
        return 0

#### Main code
if __name__ == '__main__':
    import argparse
    import ConfigParser

    # Command: Delete
    def delete():
        if (args.attachid == None and (args.ticketapp == None and args.ticket == None)):
            error_str = 'ERROR: Ticket app and ticket # pair or attachment id required'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        # CAPS interface setup
        if (access_key != None and secret_key != None):
            c = CAPSREST(system=tgt_system, access_key=access_key, secret_key=secret_key)
            if args.debug:
                c.set_debug(1)
            if args.fiddler:
                c.set_fiddler(1, {'http':fiddler_http, 'https':fiddler_https}, fiddler_cert)
        else:
            error_str = 'Error: CAPSV access and secret keys not configured.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        attachments = []
        if args.attachid != None:
            attachments = [args.attachid]
        else:
            ret = c.get_ticket(args.ticketapp, args.ticket)
            if (ret):
                # Captured error
                c.dump_debug()
                error_str = 'Error: Failed to fetch attachments.'
                logging.error(error_str)
                print error_str
                sys.exit(exit_codes['ATTACHMENT_FETCH_FAILURE'])

            for attachment in c.http_json:
                if (attachment['retention_days'] == None or attachment['retention_days'] > 1): # TODO: Change this test to > 0 once CAPS-471 is resolved
                    # Prepare to delete this attachment
                    attachments.append(attachment['id'])
                else:
                    # Attachment already deleted or set to delete
                    warning_str = 'WARNING: Attachment '+attachment['id']+' is already set for deletion. No action taken.'
                    logging.warning(warning_str)
                    print(warning_str)

        if (len(attachments) == 0):
            c.dump_debug()
            warning_str = 'WARNING: No attachments to delete.'
            logging.warning(warning_str)
            print warning_str
            sys.exit(exit_codes['NO_ATTACHMENTS'])

        # Use err as a flag for a captured error as we iterate through the list of attachments.
        # We will delete as many of the attachments as we can, log any errors, and exit with errors later.
        err = 0
        for attachment in attachments:
            ret = c.delete_attachment(attachment)
            if ret == 0:
                print 'Attachment deleted: '+attachment
            else:
                # Failure
                c.dump_debug()
                error_str = 'Error: Attachment '+attachment+' failed to delete.'
                logging.error(error_str)
                print error_str
                err = 1
        if err:
            sys.exit(exit_codes['ATTACHMENT_DELETE_FAILURE'])
        else:
            sys.exit(exit_codes['SUCCESS'])

    # Command: Download
    # TODO: Implement (when needed)
    def download():
        err = 0
        if (args.attachid == None):
            error_str = 'ERROR: Ticket app and ticket # pair or attachment id required'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        if (args.dldir == None):
            dlpath= os.getcwd()
            dlpath += os.sep
            print "Setting current Path As Path for downloading File",dlpath

        elif(args.dldir != None):
            dlpath= args.dldir
            print "Setting User Specified Path As Path for downloading File",dlpath

        # CAPS interface setup
        if (access_key != None and secret_key != None):
            c = CAPSREST(system=tgt_system, access_key=access_key, secret_key=secret_key)
            if args.debug:
                c.set_debug(1)
            if args.fiddler:
                c.set_fiddler(1, {'http':fiddler_http, 'https':fiddler_https}, fiddler_cert)
        else:
            error_str = 'Error: CAPSV access and secret keys not configured.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        #attachments = []
        if args.attachid != None:
            attachment = args.attachid
        err = 0
        if args.dlfiles == "all":
            print "All files in attachments to be downloaded"
            options=""
            retar = c.dl_attachment(attachment," ",dlpath)

            if retar:
                logging.info("\n success %r",retar)
                if len([x for x in retar if x != 200])>0:
                    print "error occurred during downloading file"
                else:
                    print "All Files Downloaded Successfully"
            #for ret in retar:
                    #if ret != 200:
                        #print "error occurred during downloading file"
        else:
            print "files in attachments to be downloaded are",args.dlfiles
            options=args.dlfiles.split(',')
            #print "Files Needed to be Downloaded as specified in CLI Command",options
            for option in options:
                ret = c.dl_attachment(attachment,option,dlpath)
                if ret:
                    if ret != 200:
                        # Failure
                        error_str = 'Error: Attachment '+attachment+' failed to download.'
                        logging.error(error_str)
                        print error_str
                        err = 1
                    elif ret == 200:
                        logging.info("\n success %r",ret)
                else:
                    print "Error: Attachment "+attachment+" failed to download.",ret
                    error_str = 'Error: Attachment '+attachment+' failed to download.'
                    logging.error(error_str)
                    err = 1
        if err:
            sys.exit(exit_codes['ATTACHMENT_LISTING_FAILURE'])
        else:
            sys.exit(exit_codes['SUCCESS'])

    # Command: list
    def listprint():
        err = 0
        if (args.attachid == None and (args.ticketapp == None or args.ticket == None)):
            error_str = 'ERROR: Ticket app and ticket # pair or attachment id required'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        # CAPS interface setup
        if (access_key != None and secret_key != None):
            c = CAPSREST(system=tgt_system, access_key=access_key, secret_key=secret_key)
            if args.debug:
                c.set_debug(1)
            if args.fiddler:
                c.set_fiddler(1, {'http':fiddler_http, 'https':fiddler_https}, fiddler_cert)
        else:
            error_str = 'Error: CAPSV access and secret keys not configured.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        attachments = []
        if args.attachid != None:
            attachments = [args.attachid]
        else:
            ret = c.get_ticket(args.ticketapp, args.ticket)
            if (ret):
                # Captured error
                c.dump_debug()
                error_str = 'Error: Failed to fetch attachments.'
                logging.error(error_str)
                print error_str
                sys.exit(exit_codes['ATTACHMENT_FETCH_FAILURE'])

            for attachment in c.http_json:
                attachments.append(attachment['id'])
                # if (attachment['retention_days'] == None or attachment['retention_days'] > 1): # TODO: Change this test to > 0 once CAPS-471 is resolved
                    # # Prepare to delete this attachment
                # else:
                    # # Attachment already deleted or set to delete
                    # warning_str = 'WARNING: Attachment '+attachment['id']+' is expired . No action taken.'
                    # logging.warning(warning_str)
                    # print(warning_str)

        if (len(attachments) == 0):
            c.dump_debug()
            warning_str = 'WARNING: No attachments to Fetch found with these ticket/attachement values.'
            logging.warning(warning_str)
            print warning_str
            sys.exit(exit_codes['NO_ATTACHMENTS'])

        # Use err as a flag for a captured error as we iterate through the list of attachments.
        # We will delete as many of the attachments as we can, log any errors, and exit with errors later.
        err = 0
        if args.listoptions == "name,status":
            t = PrettyTable(['Attachment Id','Name','Status'])
            print "Default Options for listing is being used"
        else:
            #customlist = True
            options=args.listoptions.split(',')
            options=[x.title() for x in options]
            options.insert(0,'Attachment Id')
            #print "options",options
            t = PrettyTable(options)
        print "Total Attachments to be Listed",len(attachments) 
        if len(attachments)> 5:
            print "Processing to prepare Table , Please wait ...."
        for attachment in attachments:
            ret,val = c.list_attachment(attachment)
            if ret != 200:
                # Failure
                error_str = 'Error: Attachment '+attachment+' failed to list.'
                logging.error(error_str)
                if val:
                    print val
                err = 1
            elif ret == 200:
                #pass
                if val:
                    list_item = val.json()
                    #if len([i for i in list_item['files'] if i['type']!='original']) == 0:
                    if len([i for i in list_item['files'] if i['type'] not in ('original', 'scrambledmetrics', 'scrambledlog')]) == 0:
                        print "No files Present which can be Listed" 
                        sys.exit(exit_codes['ATTACHMENT_LISTING_FAILURE'])
                    #for ele in [x for x in list_item['files'] if x['type'] != 'original']:
                    for ele in [x for x in list_item['files'] if x['type'] not in ('original', 'scrambledmetrics', 'scrambledlog')]:
                        if args.listoptions == "name,status":
                            #print "Attachment"+attachment+"NAME"+ele['name'].encode("utf-8")+"STATUS"+ele['status']
                            t.add_row([attachment,ele['name'].encode("utf-8"), ele['status']])
                        else:
                            form = [attachment]
                            for x in args.listoptions.split(','):
                                if x == 'name':
                                    form.append(ele[x].encode("utf-8"))
                                else:
                                    try:
                                       form.append(ele[x])
                                    except KeyError as k:
                                        print "This is not a valid option",x
                                        print "Please Select from Available options like",ele.keys()
                                        sys.exit(exit_codes['ATTACHMENT_LISTING_FAILURE'])
                            t.add_row(form)
        if err:
            #print "Some Error might have have occurred please check logs for more information",err
            #print t
            #if args.file:
            #    f1=open(args.file, 'w+')
            #    print >>f1,t
            #    f1.close()        
            sys.exit(exit_codes['ATTACHMENT_LISTING_FAILURE'])
        else:
            print "printing output to console"
            print t
            if args.file:
                f1=open(args.file, 'w+')
                print >>f1,t
                f1.close()        
            sys.exit(exit_codes['SUCCESS'])

    # CLI commands
    # Command: Upload
    def upload():
        # Check input
        # TODO: Come up with better solution for input scrubbing
        err = 0
        if args.customer == None:
            error_str = 'ERROR: Customer ID missing.'
            logging.error(error_str)
            print error_str
            err = 1
        if args.classification == None:
            error_str = 'ERROR: Classification ID missing.'
            logging.error(error_str)
            print error_str
            err = 1
        if args.product == None:
            error_str = 'ERROR: Product ID missing.'
            logging.error(error_str)
            print error_str
            err = 1
        if args.description == None:
            error_str = 'ERROR: Description missing.'
            logging.error(error_str)
            print error_str
            err = 1
        if args.purpose == None:
            error_str = 'ERROR: Purpose missing.'
            logging.error(error_str)
            print error_str
            err = 1
        # ticket_app and ticket are optional but needed as a pair
        # This pairing is not needed if ticketapp is REFRA (CAPS-1018)
        if ((args.ticketapp != None and args.ticketapp != "REFRA") and args.ticket == None):
            error_str = 'ERROR: Ticket app defined without Ticket #.'
            logging.error(error_str)
            print error_str
            err = 1
        if (args.ticketapp == None and args.ticket != None):
            error_str = 'ERROR: Ticket # defined without Ticket app.'
            logging.error(error_str)
            print error_str
            err = 1            
        if args.service == None:
            error_str = 'ERROR: Service class missing.'
            logging.error(error_str)
            print error_str
            err = 1

        if err == 1:
            error_str = 'Missing input parameters. Exiting.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        # Check we file minimum
        filecount = len(args.files)
        # This shouldn't happen as argsparse should keep us from getting here
        if filecount < 1:
            error_str = 'ERROR: No files defined for upload'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        # Check if file maximum limit is exceeded
        if filecount > file_limit:
            error_str = 'ERROR: File count limit ('+str(filecount)+') exceeded.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        # Check if all files exist
        for filename in args.files:
            if os.path.isfile(filename) != 1:
                error_str = 'Error: Unable to find file '+filename
                logging.error(error_str)
                print error_str
                sys.exit(exit_codes['INPUT_ERROR'])

        # CAPS interface setup
        if (access_key != None and secret_key != None):
            c = CAPSREST(system=tgt_system, access_key=access_key, secret_key=secret_key)
        else:
            error_str = 'Error: CAPSV access and secret keys not configured.'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

        if args.debug:
            c.set_debug(1)
        if args.fiddler:
            c.set_fiddler(1, {'http':fiddler_http, 'https':fiddler_https}, fiddler_cert)

        c.prepare_attachment(**vars(args))

        # Create CAPS attachment
        ret = c.create_attachment()
        if ret > 0:
            c.dump_debug()
            error_str = 'ERROR: Error during create attachment ['+str(ret)+']'
            logging.error(error_str)
            if (c.http_json != None and 'error' in c.http_json):
                if 'message' in c.http_json['error']:
                    logging.error('CAPS Response: '+c.http_json['error']['message'])                    
            sys.exit(ret)

        for filename in args.files:
            # Upload file (init, part upload, and completion handled here)
            ret = c.s3_mp_upload_file(filename)
            if ret > 0:
                c.dump_debug()
                error_str = 'ERROR: Error during upload ['+str(ret)+']'
                logging.error(error_str)
                print error_str
                if c.http_json:
                    if 'error' in c.http_json:
                        if 'message' in c.http_json['error']:
                            logging.error('CAPS Response: '+c.http_json['error']['message'])                        
                    # TODO: To enable resume, enhance this to not fail for one file in batch
                sys.exit(ret)

        # CAPSV: Update attachment state to ready
        ret = c.capsv_send_ready()
        if ret > 0:
            c.dump_debug()
            error_str = 'ERROR: Error during upload complete ['+str(ret)+']'
            logging.error(error_str)
            print error_str
            if 'error' in c.http_json:
                if 'message' in c.http_json['error']:
                    logging.error('CAPS Response: '+c.http_json['error']['message'])
            sys.exit(exit_codes['PATCH_READY_FAILURE'])

        print ''
        int_link = 'Nokia user download link : '+c.capsv_download_url
        ext_link = 'External user download link: '+c.capsv_download_url_external
        logging.info (int_link)
        print int_link
        logging.info (ext_link)
        print ext_link

    #### Input parsers

    # This  parser is specifically for handling config file. This allows us to use items in the config file as default
    # will be overridden by the main parse below.
    # We disable help here. It will be handled by the full main parser below
    conf_parser = argparse.ArgumentParser(add_help=False)

    # --version: Ouputs version and exits
    conf_parser.add_argument('-v', '--version', action='version', version=sys.argv[0]+' '+version_string)

    # Handle config file parsing
    conf_parser.add_argument('--config', metavar='FILE', help='Configuration file', action='store', type=str)

    # Parse only the portions defined and safe the remainder for the main parser below
    args, remaining_argv = conf_parser.parse_known_args()

    # Here we can define default values which will be applied if the option is not used on the command line or in the config file Default section
    defaults = {
        'log':sys.argv[0]+'.log'
    }

    # Read in config file if supplied
    if args.config:
        if os.path.isfile(args.config) != 1:
            # Logging might not be setup yet so just print error to screen
            print 'Error: Unable to find config file '+args.config
            sys.exit(exit_codes['INPUT_ERROR'])

        config = ConfigParser.SafeConfigParser()
        config.read([args.config])
        defaults.update(dict(config.items("Defaults")))

    # Main parser
    parser = argparse.ArgumentParser(parents=[conf_parser])
    parser.set_defaults(**defaults)

    # Setup subparsers and save subparser command name in command variable
    subparsers = parser.add_subparsers(dest='command')

    # Delete command parser
    parser_del = subparsers.add_parser('del', help='Delete attachments based on ticket', parents=[conf_parser])
    parser_del.set_defaults(**defaults)

    # Delete parser - hidden args
    parser_del.add_argument('--debug', help=argparse.SUPPRESS, action='store_true')
    parser_del.add_argument('--fiddler', help=argparse.SUPPRESS, action='store_true')

    # Upload parser - args
    parser_del.add_argument('--qa', help='Use QA CAPSV (Test) [Optional]', action='store_true')
    parser_del.add_argument('--log', metavar='FILE', help='Output log file (Default:'+defaults['log']+')', action='store', type=str)
    parser_del.add_argument('--cert', metavar='FILE', help='Authentication certificate file [Required]', action='store', type=str)
    parser_del.add_argument('--attachid', metavar='STRING', help='Attachment ID [Required unless ticketapp and ticket]', action='store', type=str)
    parser_del.add_argument('--ticketapp', metavar='STRING', help='Ticket application name [Required with ticket]', action='store', type=str)
    parser_del.add_argument('--ticket', metavar='STRING', help='Ticket # [Required with ticketapp]', action='store', type=str)

    # list command parser
    parser_l = subparsers.add_parser('ls', help='list attachments based on attachement id', parents=[conf_parser])
    parser_l.set_defaults(**defaults)

    # list parser - hidden args
    parser_l.add_argument('--debug', help=argparse.SUPPRESS, action='store_true')
    parser_l.add_argument('--fiddler', help=argparse.SUPPRESS, action='store_true')

    # list parser - args
    parser_l.add_argument('--qa', help='Use QA CAPSV (Test) [Optional]', action='store_true')
    parser_l.add_argument('--log', metavar='FILE', help='Output log file (Default:'+defaults['log']+')', action='store', type=str)
    parser_l.add_argument('--file', metavar='FILE', help='Write List display output to a file', action='store', type=str)
    parser_l.add_argument('--listoptions', metavar='STRING', help='Provide inputs to be included in List Table Give String of comma separated values as "name,status,size,type" [Optional]',default= "name,status", action='store', type=str)
    parser_l.add_argument('--cert', metavar='FILE', help='Authentication certificate file [Required]', action='store', type=str)
    parser_l.add_argument('--attachid', metavar='STRING', help='Attachment ID [Required unless ticketapp and ticket]', action='store', type=str)
    parser_l.add_argument('--ticketapp', metavar='STRING', help='Ticket application name [Required with ticket]', action='store', type=str)
    parser_l.add_argument('--ticket', metavar='STRING', help='Ticket # [Required with ticketapp]', action='store', type=str)

    # Download command parser
    # TODO: Implement download when needed
    parser_dl = subparsers.add_parser('dl', help='File download', parents=[conf_parser])
    parser_dl.set_defaults(**defaults)
    # download parser -hidden args
    parser_dl.add_argument('--debug', help=argparse.SUPPRESS, action='store_true')
    parser_dl.add_argument('--fiddler', help=argparse.SUPPRESS, action='store_true')
    # download parser - args
    parser_dl.add_argument('--qa', help='Use QA CAPSV (Test) [Optional]', action='store_true')
    parser_dl.add_argument('--log', metavar='FILE', help='Output log file (Default:'+defaults['log']+')', action='store', type=str)
    parser_dl.add_argument('--dldir', metavar='STRING', help='system Path to store downloaded files [Optional] default path will be current path',action='store', type=str)
    parser_dl.add_argument('--dlfiles', metavar='STRING', help='files which are needed to be downloaded Given in quoted string "1.txt,2.zip,3.zip" [Optional] if not given all files will get downloaded',default= "all", action='store', type=str)
    parser_dl.add_argument('--cert', metavar='FILE', help='Authentication certificate file [Required]', action='store', type=str)
    parser_dl.add_argument('--attachid', metavar='STRING', help='Attachment ID [Required unless ticketapp and ticket]', action='store', type=str)

    # Upload command parser
    parser_ul = subparsers.add_parser('ul', help='File upload', parents=[conf_parser])
    parser_ul.set_defaults(**defaults)

    # Upload parser - hidden args
    parser_ul.add_argument('--debug', help=argparse.SUPPRESS, action='store_true')
    parser_ul.add_argument('--fiddler', help=argparse.SUPPRESS, action='store_true')

    # Upload parser - args
    parser_ul.add_argument('--qa', help='Use QA CAPSV (Test) [Optional]', action='store_true')
    parser_ul.add_argument('--log', metavar='FILE', help='Output log file [Optional, Default:'+defaults['log']+']', action='store', type=str)
    parser_ul.add_argument('--cert', metavar='FILE', help='Authentication certificate file [Required]', action='store', type=str)
    parser_ul.add_argument('--customer', metavar='NUM', help='Customer ID NUMber [Required]', action='store', type=int)
    parser_ul.add_argument('--classification', metavar='NUM', help='Classification ID NUMber [Required]', action='store', type=int)
    parser_ul.add_argument('--product', metavar='STRING', help='Product CBD ID [Required]', action='store', type=str)
    parser_ul.add_argument('--productrel', metavar='STRING', help='Product Release CBD ID [Optional-Recommended]', action='store', type=str)
    parser_ul.add_argument('--description', metavar='STRING', help='Description [Required]', action='store', type=str)
    parser_ul.add_argument('--purpose', metavar='STRING', help='Purpose [Required]', action='store', type=str)
    parser_ul.add_argument('--service', metavar='STRING', help='Service Class [Required]', action='store', type=str)
    parser_ul.add_argument('--ticketapp', metavar='STRING', help='Ticket application name [Optional]', action='store', type=str)
    parser_ul.add_argument('--ticket', metavar='STRING', help='Ticket # [Optional]', action='store', type=str)
    parser_ul.add_argument('--retention', metavar='NUM', help='NUM days to retain data [Required]', action='store', type=int)
    parser_ul.add_argument('--emaillist', metavar='STRING', help='emaillist [Optional] Comma or semicolon delimited list of Emails to notify of log processing completion.', action='store', type=str)
    parser_ul.add_argument('--datatypecode', metavar='STRING', help='datatypecode [Optional] Ticket App should be REFRA.', action='store', type=str)
    parser_ul.add_argument('files', metavar='FILE', help='Files to upload [Required, MAX:'+str(file_limit)+']', nargs='+', type=str)

    # Parse args
    args = parser.parse_args(remaining_argv)
    
    # Setup logging
    if args.log:
        logging.basicConfig(filename=args.log, format='%(asctime)s %(levelname)s:%(message)s',level=logging.INFO)
    else:
        logging.basicConfig(filename='log.txt', format='%(asctime)s %(levelname)s:%(message)s',level=logging.INFO)
        

    if args.qa:
        tgt_system = 'qa'
    else:
        tgt_system = 'production'
    
    # Setup Fiddler (Debug)
    if args.fiddler:
        fiddler_err = 0
        if config.has_section('Fiddler'):
            if config.has_option('Fiddler', 'Fiddler_cert'):
                fiddler_cert = config.get('Fiddler', 'Fiddler_cert')
            else:
                logging.error('Fiddler cert not defined')
                fiddler_err = 1
            if config.has_option('Fiddler', 'Fiddler_http_proxy'):
                fiddler_http = config.get('Fiddler', 'Fiddler_http_proxy')
            else:
                logging.error('Fiddler http proxy not defined')
                fiddler_err = 1
            if config.has_option('Fiddler', 'Fiddler_https_proxy'):
                fiddler_https = config.get('Fiddler', 'Fiddler_https_proxy')
            else:
                logging.error('Fiddler https proxy not defined')
                fiddler_err = 1
        else:
            fiddler_err = 1

        if fiddler_err:
            error_str = 'ERROR: fiddler option used but fiddler settings not configured'
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])

    # Read in cert file if given as command line switch
    if args.cert != None:
        token_file = args.cert
        tokens = open(token_file, 'r').read().strip()
        access_key, secret_key = tokens.split(':')
        if (access_key == None or secret_key == None):
            error_str = 'ERROR: Unable to read access and secret keys from cert file '+args.cer
            logging.error(error_str)
            print error_str
            sys.exit(exit_codes['INPUT_ERROR'])
    else:
        if (access_key == None or secret_key == None):
            error_str = 'ERROR: cert not defined. Use -cert or define cert in config file'
            logging.error(error_str)
            print error_str
            print 'See '+sys.argv[0]+' '+args.command+' -h for more information.'
            sys.exit(exit_codes['INPUT_ERROR'])

    logging.info('filesystem encoding: '+sys.getfilesystemencoding())

    # Handle command
    if args.command == 'ul':
        upload()
    elif args.command == 'dl':
        download()
    elif args.command == 'del':
        delete()
    elif args.command == 'ls':
        listprint()
    else:
        # Shouldn't get here, parse_args() should weed out bad input
        error_str = 'Unaccepted command:'+args.command
        logging.error(error_str)
        print error_str
        print 'See '+sys.argv[0]+' -h for more information.'
        sys.exit(exit_codes['INPUT_ERROR'])

    sys.exit(exit_codes['SUCCESS'])


