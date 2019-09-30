import PyKCS11
import sys
import base64
import logging
import os
import boto3
import json
from json import JSONEncoder

### Add flask with basic authentication.
from flask import Flask, render_template, request
from flask_basicauth import BasicAuth

application = Flask(__name__)

# Define SSM Query Function
def getEncryptedParameter(parameterName):
    client = boto3.client('ssm', region_name='us-east-1')
    response = client.get_parameter(
        Name=parameterName,
        WithDecryption=True
    )
    return (response['Parameter']['Value'])

application.config['BASIC_AUTH_USERNAME'] = getEncryptedParameter('/tknPopSvc/apiUser')
application.config['BASIC_AUTH_PASSWORD'] = getEncryptedParameter('/tknPopSvc/apiPassword')

basic_auth = BasicAuth(application)

#enable logging
logging.basicConfig(
    filename='/opt/tokenizationApi/logs/jwtTokenCloudHsm.log',
    level=logging.INFO,
    format='%(asctime)s:::%(levelname)s:::%(message)s'   
)

logging.info('------------------------------------------------------')
logging.info('-----------------Application Startup!-----------------')
logging.info('------------------------------------------------------')
logging.info('Vets First Choice JWTokenization signing via AWS CloudHSM.')
logging.info('Logging Initialized.')

# add script variables
user = getEncryptedParameter('/tknPopSvc/tknApiCloudHsmUsr')
password = getEncryptedParameter('/tknPopSvc/tknApiCloudHsmPW')
key_handle = getEncryptedParameter('/tknPopSvc/tknApiCloudHsmKeyHandle')
header_json = json.dumps({ "alg": "RS256", "typ": "JWT" })
cloudHsmDriverLocation = '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so'

# generatedJWT
class GeneratedJWT:
    def __init__(self, globalUID, jwt):
        self.globalUID = globalUID
        self.jwt = jwt

def serialize(obj):
    return obj.__dict__

def encodeJson(json):
    #logging.debug('Encoding json: ' + json)
    jsonString = str(json)
    jsonBytes = bytes(jsonString, 'utf-8')
    jsonEncoded = base64.urlsafe_b64encode(jsonBytes)
    jsonEncodedStr = str(jsonEncoded, 'utf-8')
    #logging.debug('Encoded json: ' + jsonEncodedStr)
    return jsonEncodedStr

def signJwt(request):
    logging.info('----------------Begin JWT Signing----------------')
    # load pykcs11 library and CloudHSM driver
    try:
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(cloudHsmDriverLocation)
        logging.info('PyKCS11 library and CloudHSM driver successfully loaded.')
    except:
        logging.error('Unable to load PyKCS11 library or CloudHSM driver! Exiting.')
        sys.exit(1)
    # establish CloudHSM session and authenticate
    sess = None
    try:
        slots = pkcs11.getSlotList(True)
        logging.info('Finding available HSM slot.')
        if not slots:
            logging.error("No slots found, exiting.")
            sys.exit(1)
        slot = slots[0]
        credentials = user + ":" + password
        sess = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        sess.login(credentials)
        logging.info('Login successful!')
    except:
        logging.error('Unable to establish session or authenticate.')
        sys.exit(1)
    # find correct key in HSM
    try:
        logging.info('Locating specified key handle %s on HSM.' % key_handle)
        objs = sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if len(objs) == 0:
            logging.error('No signing keys have been found. Aborting...')
        else:
            found_key = False
            for o in objs:
                if str(o.value()) == key_handle:
                    found_key = True
                    signingKey = o
                    break
            if found_key:
                logging.info("Using the RSA private key with ID %s to cryptographically sign the data..." % key_handle)
            else:
                logging.error("There's no RSA private key with ID %s. Aborting..." % key_handle)
    except:
        logging.error("Could not find key.")
    # sign JWT
    try:
        jwtCount = 0
        #logging.info("Signing client_guid: " + client_guid)
        try:
            logging.debug('Encoding header: ' + str(header_json))
            headerEncodedStr = encodeJson(header_json)
            logging.debug('Header encoded: ' + headerEncodedStr)
        except:
            logging.error('Error encoding header.')
        try:
            globalUID = ()
            listGeneratedJWT = []
            for req in request['jwtRequest']:
                globalUID = req['globalUID']
                try:
                    if 'globalUID' in req:
                        del req['globalUID']
                        payloadEncodedStr = encodeJson(json.dumps(req))
                        logging.debug('Payload encoded: ' + payloadEncodedStr)
                except:
                        logging.error('Error encoding payload.')
                headerPayload = headerEncodedStr + '.' + payloadEncodedStr
                signature = sess.sign(signingKey, headerPayload, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None))
                # convert signature to bytes type, then base64 encode
                byteSignature = bytes(signature)
                byteSignatureEncoded = base64.urlsafe_b64encode(byteSignature)
                byteSignatureEncodedStr = str(byteSignatureEncoded,'utf-8')
                jwt = headerPayload + '.' + byteSignatureEncodedStr
                logging.debug('JWT Created: ' + jwt)
                generatedJwt = GeneratedJWT(globalUID, jwt)
                listGeneratedJWT.append(generatedJwt)
                jwtCount = jwtCount + 1
        except:
            logging.error('Error signing JWT.')
    except:
        logging.error('Could not create JWT.')
    logging.info(str(jwtCount) + ' JWTs created this session.')
    # logout
    try:
        sess.logout()
        sess.closeSession()
        logging.info('Session was successfully closed.')
    except:
        logging.error('Unable to properly close session.')
    logging.info('----------------Finish JWT Signing----------------')
    return json.dumps(listGeneratedJWT, default=serialize)

@application.route('/jwts', methods=['POST'])
@basic_auth.required
def batchJwts():
    req_data = request.get_json()
    jwtArray = signJwt(req_data)
    return jwtArray

if __name__ == "__main__":
    application.run(host='0.0.0.0')
