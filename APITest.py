import os
import requests
import logging
import json
from hvac import Client as VaultClient
import http.client as http_client
from datetime import datetime, timedelta

AMI_URL = 'https://www.ami-central.com:1985/MBService'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

print(requests.get('http://ip.42.pl/raw').text)


def chunk_list(l, n):
    """ Yield n-sized chunks of l """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def login():
    username = 'brian.boothe@pentair.com'
    password = 'Password123$'
    resp = requests.post(AMI_URL + '/Login', json={'username': username, 'password': password})
    if resp.status_code == 200:
        return resp.json()['token']
    else:
        raise Exception(resp)

def login_vault():
    if 'VAULT_TOKEN' in os.environ:
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
    #http_client.HTTPConnection.debuglevel = 1
    #logging.basicConfig()
    #logging.getLogger().setLevel(logging.DEBUG)
    #requests_log = logging.getLogger("requests.packages.urllib3")
    #requests_log.setLevel(logging.DEBUG)
    #requests_log.propagate = True
    device_id = device['SID']
    values = []
    try:
        registers = json.loads(device['SENSOR_REGISTERS'])
        for group in chunk_list(registers, 40):
            body = {'DeviceID': device_id,
                'FromDate': (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'),
                'ToDate': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
            resp = requests.post(AMI_URL + '/GetAllLoggedRegistersData', headers={'Authorization': 'token:' + token, 'Content-Type': 'application/json; charset=utf-8'}, json=body)
            #values.extend(resp.json()['RegisterValues'])
            #print(resp.json())
        print('%s Success!' % device_id)
    except Exception as e:
        print('%s Fail: %s' % (device_id, e))


def run(run_local=False):
    with open('data_models.json') as f:
        data_models = json.loads(f.read())
    token = login_vault()
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
    #with open('data_models.json') as f:
    #    dms = json.loads(f.read())
    #    dm = [d for d in dms if d['SID'] == '16122'][0]
    #get_register_values(device=dm, token=login_vault())
    if 'device' in event:
        get_register_values(**event)
    else:
        run()


if __name__ == '__main__':
    run(True)
