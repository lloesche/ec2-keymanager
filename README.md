# ec2-keymanager
Quickly swap out EC2 SSH Keys

Example: replace key 'lukas' in all regions with the key in ~/.ssh/id_rsa.pub
```
./keymanager.py -v -n lukas -f ~/.ssh/id_rsa.pub
```

```
usage: keymanager.py [-h] [--verbose] [--access-key-id ACCESS_KEY_ID]
                     [--secret-access-key SECRET_ACCESS_KEY]
                     [--region REGION [REGION ...]] --name KEY_NAME
                     [--file KEY_FILE] [--list] [--yes]

Generate AWS IAM User Report

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Verbose logging
  --access-key-id ACCESS_KEY_ID, -k ACCESS_KEY_ID
                        AWS Access Key ID
  --secret-access-key SECRET_ACCESS_KEY, -s SECRET_ACCESS_KEY
                        AWS Secret Key
  --region REGION [REGION ...], -r REGION [REGION ...]
                        AWS Region (default: all)
  --name KEY_NAME, -n KEY_NAME
                        Key Name
  --file KEY_FILE, -f KEY_FILE
                        Key File
  --list, -l            List Keys
  --yes, -y             Assume YES to all questions
  ```
  
