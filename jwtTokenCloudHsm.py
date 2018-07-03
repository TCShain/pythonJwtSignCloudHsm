import PyKCS11
import sys
import argparse
import getpass
import base64
import logging

#enable logging
logging.basicConfig(
    #filename='test.log',
    level=logging.INFO,
    format='%(asctime)s:::%(levelname)s:::%(message)s'   
)
logging.info('Logging Initialized.')

# load pykcs11 library and CloudHSM driver
try:
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load('/opt/cloudhsm/lib/libcloudhsm_pkcs11.so')
    logging.info('PyKCS11 library and CloudHSM driver successfully loaded.')
except:
    logging.error('Unable to load PyKCS11 library or CloudHSM driver! Exiting.')
    sys.exit(1)

# acquire credentials
# may need to rework this section inorder to have script called progrmmatically, if we choose to use this python code for automated JWT creation
parser = argparse.ArgumentParser(description='Enter parameters.')

class PasswordPromptAction(argparse.Action):
    def __init__(self,
             option_strings,
             dest=None,
             nargs=0,
             default=None,
             required=False,
             type=None,
             metavar=None,
             help=None):
        super(PasswordPromptAction, self).__init__(
             option_strings=option_strings,
             dest=dest,
             nargs=nargs,
             default=default,
             required=required,
             metavar=metavar,
             type=type,
             help=help)

    def __call__(self, parser, args, values, option_string=None):
        password = getpass.getpass()
        setattr(args, self.dest, password)

# add credential parameters
parser.add_argument('-u', dest='user', type=str, required=True)
parser.add_argument('-p', dest='password', action=PasswordPromptAction, type=str, required=True)
# add key_handle parameter
parser.add_argument('-k', dest='key_handle', type=str, required=True)
# add input and output file parameters
parser.add_argument('--in', dest='in_file', type=argparse.FileType('r'), required=True)
#parser.add_argument('-out', dest='out_file', type=argparse.FileType('w'), required=True)

args = parser.parse_args()

# establish CloudHSM session and authenticate
sess = None
try:
    slots = pkcs11.getSlotList(True)
    logging.info('Finding available HSM slot.')
    if not slots:
        logging.error("No slots found, exiting.")
        sys.exit(1)

    if args.password:
        passwd = args.password
    else:
        logging.error('Password value cannot be blank.')
        sys.exit(1)
    
    slot = slots[0]
    credentials = args.user + ":" + passwd
    sess = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    sess.login(credentials)
    logging.info('Login successful!')
except:
    logging.error('Unable to establish sesion or authenticate.')

# find correct key in HSM
try:
    logging.info('Locating specified key handle %s on HSM.' % args.key_handle)
    objs = sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
    if len(objs) == 0:
        logging.error('No signing keys have been found. Aborting...')
    else:
        found_key = False
        for o in objs:
            if str(o.value()) == args.key_handle:
                found_key = True
                signingKey = o
                break
        if found_key:
            logging.info("Using the RSA private key with ID %s to cryptographically sign the data..." % args.key_handle)
        else:
            logging.error("There's no RSA private key with ID %s. Aborting..." % args.key_handle)
except:
    logging.error("Could not find key.")

# sign JWT

try:
    infile = args.in_file
    jwtCount = 0
    alg = 'alg'
    sub = 'sub'
    for line in infile:
        if alg in line:
            try:
                logging.debug('Encoding header: ' + line)
                header = bytes(line, 'utf-8')
                headerEncoded = base64.urlsafe_b64encode(header)
                headerEncodedStr = str(headerEncoded, 'utf-8')
                logging.debug('Header encoded: ' + headerEncodedStr)
            except:
                logging.error('Error encoding header.')
        elif sub in line:
            try:
                logging.debug('Encoding payload: ' + line)
                payload = bytes(line, 'utf-8')
                payloadEncoded = base64.urlsafe_b64encode(payload)
                payloadEncodedStr = str(payloadEncoded, 'utf-8')
                logging.debug('Payload encoded: ' + payloadEncodedStr)
            except:
                logging.error('Error encoding payload.')
            try:
                headerPayload = headerEncodedStr + '.' + payloadEncodedStr
                signature = sess.sign(signingKey, headerPayload, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None))
                # convert signature to bytes type, then base64 encode
                byteSignature = bytes(signature)
                byteSignatureEncoded = base64.urlsafe_b64encode(byteSignature)
                byteSignatureEncodedStr = str(byteSignatureEncoded,'utf-8')
                logging.debug('JWT Created: ' + headerPayload + '.' + byteSignatureEncodedStr)
                jwtCount = jwtCount + 1
            except:
                logging.error('Error signing headerPayload.')
except:
    logging.error('Could not create JWT.')

logging.info(str(jwtCount) + ' JWTs created.')

# logout
try:
    sess.logout()
    sess.closeSession()
    print('Session was successfully closed.')
except:
    print('Unable to properly close session.')
