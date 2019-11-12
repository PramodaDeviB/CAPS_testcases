#!/usr/bin/python
import os
import re
import sys
import logging
import ssl
import argparse
import paramiko

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(message)s')

class sshconnect:
	def ssh_connect(self,hostname,uname,pwd):
	    try:
	        client = paramiko.SSHClient()
	        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	        client.connect(hostname,username=uname,password=pwd)
	    except paramiko.AuthenticationException:
	        print("Authentication failed, please verify your credentials: %s")
	    except paramiko.SSHException as sshException:
	        print("Unable to establish SSH connection: %s" % sshException)
	    except paramiko.BadHostKeyException as badHostKeyException:
	        print("Unable to verify server's host key: %s" % badHostKeyException)
	    else:
	        return client

	def ssh_execute_command(self,client,command):
	    logger.info("Executing command {}".format(command))
	    print(client)
	    print(command)
	    stdin, stdout, stderr = client.exec_command(command)
	    # result = stderr.read()
	    # if len(result)  > 0:
	    #     logger.error("hit error" + result) #except Exception as e:   print("Operation error: %s", e)
	    #     sys.exit(1)
	    # logger.info("Successfully executed command {}".format(command))
	    return stdout.read(),stdout.channel.recv_exit_status()