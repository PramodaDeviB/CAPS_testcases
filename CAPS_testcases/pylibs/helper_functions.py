#import String

def form_access_token(acces_key,secret_key,char=None):
	acces_key=acces_key.replace(char,'')
	secret_key=secret_key.replace(char,'')
	token=acces_key+":"+secret_key
	return token

def update_auth_token(file,token):
	try:
		f=open(file,'w')
		f.write(token)
	finally:
		f.close()



