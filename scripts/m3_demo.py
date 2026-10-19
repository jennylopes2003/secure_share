"""Small example of sharing an encrypted file with another user."""
import os
import tempfile
from pathlib import Path
from cryptography.exceptions import InvalidTag
from app.crypto.keystore import create_user, get_public_info, load_enc_private_key, save_dek, load_dek
from app.crypto.file_crypto import build_aad, encrypt_file, decrypt_file
from app.crypto.keywrap import wrap_key, unwrap_key


def main():
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        owner = create_user('owner', 'owner strong password', directory=folder)
        requester = create_user('requester', 'requester strong password', directory=folder)
        file_id = os.urandom(32)
        aad = build_aad(file_id, owner['address'])
        plaintext = b'SecureShare Member 3 sample confidential file'
        dek, encrypted_file = encrypt_file(plaintext, aad)
        save_dek('owner', 'owner strong password', file_id, dek, directory=folder)
        # The full application should check approval on-chain before sharing the key.
        recipient_public = get_public_info('requester', directory=folder)['enc_public_key']
        wrapped = wrap_key(load_dek('owner', 'owner strong password', file_id, directory=folder),
                           recipient_public, file_id, owner['address'], requester['address'])
        recovered_key = unwrap_key(wrapped, load_enc_private_key('requester', 'requester strong password', directory=folder),
                                   file_id, owner['address'], requester['address'])
        assert decrypt_file(recovered_key, encrypted_file, aad) == plaintext
        print('[ok] Owner encrypted a file and wrapped its AES key for the requester')
        print('[ok] Requester unwrapped the key and decrypted the original file')
        try:
            unwrap_key(wrapped, load_enc_private_key('owner', 'owner strong password', directory=folder),
                       file_id, owner['address'], requester['address'])
        except InvalidTag:
            print('[ok] Wrong recipient cannot unwrap the key')
        else:
            raise AssertionError('Wrong recipient unexpectedly unwrapped the key')

if __name__ == '__main__':
    main()
