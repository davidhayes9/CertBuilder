from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import os
import datetime


def createKey(algo):

    # Generate a key pair
    if algo == 'rsa':    
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return rsa_key

    if algo == 'ec':
        ec_key = ec.generate_private_key(ec.SECP256R1())
        return ec_key    


def createCSR(private_key, user_csr_input):

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, user_csr_input['country_code']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, user_csr_input['state']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, user_csr_input['location']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, user_csr_input['org_name']),
        x509.NameAttribute(NameOID.COMMON_NAME, user_csr_input['common_name']),
    ])

    #san_dns_list = [x509.DNSName(fqdn) for fqdn in user_csr_input['san_dns']]

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(fqdn) for fqdn in user_csr_input['san_dns']]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    return csr


def collectUserInputs():

    common_name = input("Common Name for use in subject: ").strip()
    country_code = input("Two-Letter Country Code for use in subject: ").strip()
    state = input("State for use in subject: ").strip()
    location = input("Locality Name for use in subject: ").strip()
    org_name = input("Organization Name for use in subject: ").strip()
    #org_unit_name = input("Organization Unit Name for use in subject: ").strip()
    email_add = input("Email address for use in subject: ").strip()
    #san_ip = input("IP addresses (space separated) for use in subject-alternative-name: ").strip().split(' ')
    san_dns = input("DNS names (space separated) for use in subject-alternative-name: ").strip().split(' ')


    user_csr_input = {
        'common_name': common_name,
        'country_code': country_code,
        'state': state,
        'location': location,
        'org_name': org_name,
        # 'org_unit_name': org_unit_name,
        'email_add': email_add,
        # 'san_ip': san_ip,
        'san_dns': san_dns
    }

    return user_csr_input


def writeKey(private_key, cn):

    key_name = cn + '.key'

    # Save the key to a file
    with open(key_name, "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
        ))

     # Let the user know where we are writing the file
    key_location = os.getcwd() + '/' + key_name
    print(f'KEY saved to {key_location}')


def writeCert(cert, cn, cert_type):

    csr_name = cn + '.' + cert_type

    with open(csr_name, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Let the user know where we are printing the file
    cert_location = os.getcwd() + '/' + csr_name
    print(f'{cert_type.upper()} saved to {cert_location}')


def createCA(user_csr_input):

    ca_key = createKey('ec')

    # subject == issuer for CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, user_csr_input['country_code']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, user_csr_input['state']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, user_csr_input['location']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, user_csr_input['org_name']),
        x509.NameAttribute(NameOID.COMMON_NAME, 'My Real Root CA'),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for ~10 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False,
    ).sign(ca_key, hashes.SHA256())

    return ca_cert, ca_key


def signCSR(csr, ca_cert, ca_key):
    
    #san_extension = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    #print(f'{san_extension=}')

    signed_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Certificate will be valid for 2 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*2)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # add SAN from CSR to signed cert
    ).add_extension(
        x509.SubjectAlternativeName(csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value),
        critical=False,
    # Sign certificate with CA private keys
    ).sign(ca_key, hashes.SHA256())

    return signed_cert


def main():

    private_key = createKey('rsa')
    
    user_csr_input = collectUserInputs()

    csr = createCSR(private_key, user_csr_input)    

    writeKey(private_key, user_csr_input['common_name'])
    writeCert(csr, user_csr_input['common_name'], 'csr')

    print()
    answer = input("Would you like to create a CA and sign the CSR with it? [y/n] ")
    if answer == 'y':

        ca_cert, ca_key = createCA(user_csr_input)
        writeKey(ca_key, 'CA')
        writeCert(ca_cert, 'CA', 'crt')
        signed_cert = signCSR(csr, ca_cert, ca_key)
        writeCert(signed_cert, user_csr_input['common_name'], 'crt')


if __name__ == "__main__":
    main()