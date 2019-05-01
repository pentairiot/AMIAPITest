## Run locally

```
pip install -r requirements.txt
python APITest.py
```

## Deploy with serverless

```
npm i serverless serverless-pseudo-parameters serverless-python-requirements
sls deploy
```

## Run on AWS

1. Go to the deployed function, create a test event with contents `{}` and click Test
2. Check APITest log streams in Cloudwatch events
