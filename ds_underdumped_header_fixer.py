#!/usr/bin/env python3.9
import argparse
import hashlib

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('GH_FILE')
    parser.add_argument('ROM_TO_FIX')
    return parser.parse_args()

def get_sha1(input_file):
    sha1_hash_obj = hashlib.sha1()
    while True:
        data = input_file.read(65536)
        if not data:
            break
        sha1_hash_obj.update(data)

    return sha1_hash_obj.hexdigest()

def get_expected_sha1(gh_file):
    sha1_prefix = 'SHA1:               '
    for line in gh_file:
        if line.startswith(sha1_prefix):
            expected_sha1 = line.removeprefix(sha1_prefix).lower().strip()
            break
    return expected_sha1

def get_header_values(gh_file):
    header_values = {}
    prefixes = {'banner_sha1_hmac': 'BannerSHA1HMAC:     0x',
                'reserved_6': 'Reserved6:          0x',
                'rsa_signature': 'RSASignature:       0x'}
    
    for line in gh_file:
        if line.startswith(prefixes['banner_sha1_hmac']):
            header_values['banner_sha1_hmac'] = \
            bytes.fromhex(line.removeprefix(prefixes['banner_sha1_hmac'])\
            .strip())[::-1]
        elif line.startswith(prefixes['reserved_6']):
            header_values['reserved_6'] = \
            bytes.fromhex(line.removeprefix(prefixes['reserved_6'])\
            .strip())
        elif line.startswith(prefixes['rsa_signature']):
            header_values['rsa_signature'] = \
            bytes.fromhex(line.removeprefix(prefixes['rsa_signature'])\
            .strip())[::-1]
    return header_values

def insert_header_values(header_values, rom_to_fix):
    offsets = {'banner_sha1_hmac': 0x33C,
               'reserved_6': 0x378,
               'rsa_signature': 0xF80}
    
    for offset_name, offset in offsets.items():
        rom_to_fix.seek(offset)
        rom_to_fix.write(header_values[offset_name])

def main():
    args = get_args()
    with open(args.GH_FILE, 'rt') as gh_file, \
         open(args.ROM_TO_FIX, 'rb+') as rom_to_fix:
             expected_sha1 = get_expected_sha1(gh_file)
             header_values = get_header_values(gh_file)
             insert_header_values(header_values, rom_to_fix)
             rom_to_fix.seek(0)
             actual_sha1 = get_sha1(rom_to_fix)
    if expected_sha1 != actual_sha1:
        raise ValueError(f'ROM file SHA1 mismatch.\n'\
                         f'Expecting: {expected_sha1}\n'\
                         f'Got:       {actual_sha1}')

if __name__ == '__main__':
    main()
