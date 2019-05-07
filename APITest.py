import os
from hvac import Client as VaultClient
import requests
import logging
import json
import http.client as http_client

AMI_URL = 'https://www.ami-central.com:1985/MBService'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

print(requests.get('http://ip.42.pl/raw').text)

http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

def chunk_list(l, n):
    """ Yield n-sized chunks of l """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def login(vault_token=None):
    """
    Get username and password from Vault, login and return token
    :param vault_token:
    :return:
    """
    if vault_token is None and 'VAULT_TOKEN' in os.environ:
        vault_token = os.environ['VAULT_TOKEN']
    else:
        raise Exception('Vault token not defined')
    vc = VaultClient(url='https://vault.pentair.io', token=vault_token)
    vc.renew_token()
    secret = vc.read('secret/data/lambdas/ami')
    username = secret['data']['data']['username']
    password = secret['data']['data']['password']
    resp = requests.post(AMI_URL + '/Login', json={'username': username, 'password': password})
    if resp.status_code == 200:
        return resp.json()['token']
    else:
        raise Exception(resp)


def get_register_values(device, token):
    device_id = device['SID']
    values = []
    try:
        registers = json.loads(device['SENSOR_REGISTERS'])
        for group in chunk_list(registers, 40):  # 40 = limit of readings in one call
            body = {'DeviceID': device['SID'],
                    'Registers': [
                        {
                            "RegisterAddress": int(sid.split('-')[1]),
                            "SlaveID": int(sid.split('-')[2]),
                            "BusIndex": int(sid.split('-')[3])
                        } for sid in group
                    ]}
            resp = requests.post(AMI_URL + '/GetRegistersValues', headers={
                'Authorization': 'token:' + token,
                'Content-Type': 'application/json; charset=utf-8'
            }, json=body)
            req = resp.request
            #print('{}\n{}\n{}\n\n{}'.format('-----------START-----------', req.method + ' ' + req.url, '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()), req.body,))
            #print('{}\n{}\n{}\n\n{}'.format('-----------START-----------', req.url, '\n'.join('{}: {}'.format(k, v) for k, v in resp.headers.items()), resp.text,))
            print('---------------------------------------------SENT-----------------------------------------------')
            values.append(resp.json()['RegisterValues'])
        print('%s Success!' % device_id)
    except Exception as e:
        print('%s Fail: %s' % (device_id, e))


def run(run_local=False):
    with open('data_models.json') as f:
        data_models = json.loads(f.read())
    token = login()
    print('Logged in to AMI API')
    if run_local:
        for device in data_models:
            get_register_values(device, token)
    else:
        import boto3
        client = boto3.client('lambda')
        for device in data_models:
            client.invoke(FunctionName='APITest', InvocationType='Event',
                          Payload=json.dumps({'device': device, 'token': token}))


def lambda_handler(event, context):
    if 'device' in event:
        get_register_values(**event)
    else:
        run()


if __name__ == '__main__':
    #run(True)
    get_register_values(device={
  "SENSOR_REGISTERS": "[\"16168-0-254-0\", \"16168-1-254-0\", \"16168-2-254-0\", \"16168-3-254-0\", \"16168-4-254-0\", \"16168-5-254-0\", \"16168-6-254-0\", \"16168-7-254-0\", \"16168-8-254-0\", \"16168-9-254-0\", \"16168-10-254-0\", \"16168-11-254-0\", \"16168-12-254-0\", \"16168-13-254-0\", \"16168-14-254-0\", \"16168-15-254-0\", \"16168-18-254-0\", \"16168-21-254-0\", \"16168-30-254-0\", \"16168-31-254-0\", \"16168-50-254-0\", \"16168-51-254-0\", \"16168-52-254-0\", \"16168-53-254-0\", \"16168-56-254-0\", \"16168-57-254-0\", \"16168-58-254-0\", \"16168-59-254-0\", \"16168-60-254-0\", \"16168-61-254-0\", \"16168-64-254-0\", \"16168-65-254-0\", \"16168-66-254-0\", \"16168-67-254-0\", \"16168-68-254-0\", \"16168-69-254-0\", \"16168-70-254-0\", \"16168-71-254-0\", \"16168-72-254-0\", \"16168-73-254-0\", \"16168-74-254-0\", \"16168-75-254-0\", \"16168-76-254-0\", \"16168-77-254-0\", \"16168-78-254-0\", \"16168-79-254-0\", \"16168-80-254-0\", \"16168-81-254-0\", \"16168-82-254-0\", \"16168-83-254-0\", \"16168-84-254-0\", \"16168-85-254-0\", \"16168-86-254-0\", \"16168-87-254-0\", \"16168-100-254-0\", \"16168-101-254-0\", \"16168-102-254-0\", \"16168-103-254-0\", \"16168-104-254-0\", \"16168-112-254-0\", \"16168-113-254-0\", \"16168-114-254-0\", \"16168-115-254-0\", \"16168-116-254-0\", \"16168-117-254-0\", \"16168-118-254-0\", \"16168-119-254-0\", \"16168-120-254-0\", \"16168-121-254-0\", \"16168-122-254-0\", \"16168-123-254-0\", \"16168-124-254-0\", \"16168-125-254-0\", \"16168-0-4-0\", \"16168-0-9-0\", \"16168-21-9-0\", \"16168-22-9-0\", \"16168-23-9-0\", \"16168-24-9-0\", \"16168-26-9-0\", \"16168-129-9-0\", \"16168-128-9-0\", \"16168-132-9-0\", \"16168-31-254-0\"]",
  "HID": "16168 Data Model",
  "ROE_TYPE": "AMIDataModel",
  "SENSOR_CURSOR": "16168-cursor",
  "WRITESTAMP": "2019-04-03T13:35:14Z",
  "RECEIVESTAMP": "2019-04-03T13:35:03Z",
  "SID": "16168",
  "DEVICE_NAME": "16168 Vapor X ELS61",
  "ROE_SITE": "16168",
  "IS_SENSOR": "true",
  "TIMESTAMP": "!IMMASENSOR"
}, token='5uuPn/xJx06jiGV3eBZYpQ==')
