from Cryptodome.PublicKey import RSA

def gen_rsa_keys(name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(f"keys/{name}_priv.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open(f"keys/{name}_pub.pem", "wb")
    file_out.write(public_key)
    file_out.close()


def main():
    gen_rsa_keys("Joakim")

if __name__ == '__main__':
    main()