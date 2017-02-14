#!/usr/bin/env python3
import boto3
import botocore.exceptions
import sys
import argparse
import logging
from pprint import pprint

logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(logging.INFO)
log = logging.getLogger(__name__)


def main(argv):
    p = argparse.ArgumentParser(description='Generate AWS IAM User Report')
    p.add_argument('--verbose', '-v', help='Verbose logging', dest='verbose', action='store_true', default=False)
    p = KeyManager.set_args(p)
    args = p.parse_args(argv)
    if args.verbose:
        logging.getLogger('__main__').setLevel(logging.DEBUG)

    km = KeyManager(args)
    km.run()


class KeyManager:
    def __init__(self, args):
        self.args = args
        self.log = logging.getLogger(self.__class__.__name__)
        logging.getLogger(self.__class__.__name__).setLevel(logging.INFO)

        if self.args.verbose:
            logging.getLogger(self.__class__.__name__).setLevel(logging.DEBUG)

        if self.args.key_file:
            fp = open(self.args.key_file)
            self.pub_key = fp.read()
            fp.close()
        else:
            self.pub_key = None

        if not self.args.region:
            self.log.info('Region not specified, assuming all regions')
            self.regions = self.all_regions()
        else:
            self.regions = args.region

    @staticmethod
    def set_args(p):
        p.add_argument('--access-key-id', '-k', help='AWS Access Key ID', dest='access_key_id', type=str, default=None)
        p.add_argument('--secret-access-key', '-s', help='AWS Secret Key', dest='secret_access_key', type=str,
                       default=None)
        p.add_argument('--region', '-r', help='AWS Region (default: all)', dest='region', type=str, default=None,
                       nargs='+')
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument('--name', '-n', help='Key Name', dest='key_name', type=str, default=None)
        p.add_argument('--file', '-f', help='Key File', dest='key_file', type=str, default=None)
        g.add_argument('--list', '-l', help='List Keys', dest='list', action='store_true', default=False)
        p.add_argument('--yes', '-y', help='Assume YES to all questions', dest='yes', action='store_true',
                       default=False)
        return p

    def list_keys(self):
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        for region in self.regions:
            self.log.debug("Retrieving keys in region '{}'".format(region))
            ec2 = session.client('ec2', region_name=region)
            key_pairs = ec2.describe_key_pairs()
            print("Region {}".format(region))
            for k in key_pairs['KeyPairs']:
                print("\t{} (fingerprint: {})".format(k['KeyName'], k['KeyFingerprint']))

    def all_regions(self):
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        ec2 = session.client('ec2', region_name='us-west-2')
        regions = ec2.describe_regions()
        return [r['RegionName'] for r in regions['Regions']]

    def key_exists_in(self, region):
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        ec2 = session.resource('ec2', region_name=region)
        try:
            key_pair = ec2.KeyPair(self.args.key_name)
            log.debug("Key '{}' exists in region {} with fingerprint {}".format(self.args.key_name, region,
                                                                                key_pair.key_fingerprint))
            return True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                log.debug("Key '{}' doesn't exist in region {}".format(self.args.key_name, region))
                return False
            else:
                pass

    def delete_key_in(self, region):
        log.info("Deleting key '{}' in region {}".format(self.args.key_name, region))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        ec2 = session.resource('ec2', region_name=region)
        try:
            key_pair = ec2.KeyPair(self.args.key_name)
            if self.user_confirms("Do you want me to delete key '{}'?".format(self.args.key_name)):
                key_pair.delete()
                return True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                log.debug("Key '{}' doesn't exist in region {}".format(self.args.key_name, region))
                return True
            else:
                pass

    def import_key_in(self, region):
        if not self.pub_key:
            log.error("No Key File specified, unable to import new Key '{}'".format(self.args.key_name))
            return False

        log.info("Importing key '{}' in region {}".format(self.args.key_name, region))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key)
        ec2 = session.client('ec2', region_name=region)

        if self.user_confirms(
                "Do you want me to import key '{}' from '{}' ?".format(self.args.key_name, self.args.key_file)):
            ec2.import_key_pair(KeyName=self.args.key_name, PublicKeyMaterial=self.pub_key)
            return True

    def replace(self):
        if not self.pub_key:
            log.error("No Key File specified, unable to import new Key '{}'".format(self.args.key_name))
            return False

        log.info("Replacing Key '{}' in regions {}".format(self.args.key_name, ', '.join(self.regions)))
        for region in self.regions:
            if self.key_exists_in(region):
                self.delete_key_in(region)
            self.import_key_in(region)

    def user_confirms(self, question):
        if self.args.yes:
            return True

        sys.stdout.write('{} [y/N]: '.format(question))
        choice = input().lower()
        return choice.startswith('y')

    def run(self):
        if self.args.list:
            self.list_keys()
        else:
            self.replace()

if __name__ == "__main__":
    main(sys.argv[1:])
