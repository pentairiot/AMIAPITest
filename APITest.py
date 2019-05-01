import os
from hvac import Client as VaultClient
import requests
import json

AMI_URL = 'https://www.ami-central.com:1985/MBService'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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
            values.append(resp.json()['RegisterValues'])
        print('%s Success!' % device_id)
    except:
        print('%s Fail' % device_id)


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
    run(True)
