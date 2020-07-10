#!/usr/bin/env python3
import os
import re
import sys
import hvac
import argparse
RawTextHelpFormatter = argparse.RawTextHelpFormatter
import glob
import getpass
import platform
import subprocess
import ruamel.yaml
check_call = subprocess.check_call


if sys.version_info[:2] < (3, 7):
    raise Exception("Python 3.7 or a more recent version is required.")


COMMANDS = frozenset({'template',
                      'edit',
                      'clean',
                      'install',
                      'diff',
                      'view',
                      'upgrade',
                      'lint',
                      'dec',
                      'enc'})

CONFIG_ERR_MSG = 'Vault not configured correctly, check VAULT_ADDR and VAULT_TOKEN env variables.'


def parse_args(args):
    # Help text
    parser = argparse.ArgumentParser(description=
    """Store secrets from Helm in Vault

    Required Environment Variables:

    VAULT_ADDR:     (The HTTP address of Vault, for example, http://localhost:8200)
    VAULT_TOKEN:    (The token used to authenticate with Vault)
    """, formatter_class=RawTextHelpFormatter)

    subparsers = parser.add_subparsers(dest="action", required=True)

    # Encrypt help
    encrypt = subparsers.add_parser("enc", help="Parse a YAML file and store user entered data in Vault")
    encrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    encrypt.add_argument("-s", "--secret-file", type=str, help="File containing the secret for input. Must end in .yaml.dec")

    # Decrypt help
    decrypt = subparsers.add_parser("dec", help="Parse a YAML file and retrieve values from Vault")
    decrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")

    # Clean help
    clean = subparsers.add_parser("clean", help="Remove decrypted files (in the current directory)")
    clean.add_argument("-f", "--file", type=str, help="The specific YAML file to be deleted, without .dec", dest="yaml_file")

    # View Help
    view = subparsers.add_parser("view", help="View decrypted YAML file")
    view.add_argument("yaml_file", type=str, help="The YAML file to be worked on")

    # Edit Help
    edit = subparsers.add_parser("edit", help="Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.")
    edit.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    edit.add_argument("-e", "--editor", help='Editor name. Default: (Linux/MacOS) "vi" (Windows) "notepad"', const=True, nargs="?")

    # Install Help
    install = subparsers.add_parser("install", help="Wrapper that decrypts YAML files before running helm install")
    install.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")

    # Template Help
    template = subparsers.add_parser("template", help="Wrapper that decrypts YAML files before running helm template")
    template.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")

    # Upgrade Help
    upgrade = subparsers.add_parser("upgrade", help="Wrapper that decrypts YAML files before running helm upgrade")
    upgrade.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")

    # Lint Help
    lint = subparsers.add_parser("lint", help="Wrapper that decrypts YAML files before running helm link")
    lint.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")

    # Diff Help
    diff = subparsers.add_parser("diff", help="Wrapper that decrypts YAML files before running helm diff")
    diff.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")

    # Add -kv argument to each one of these
    for param in [diff, lint, upgrade, template, install, edit, view, decrypt, encrypt]:
        param.add_argument("-kv", "--kvversion",
                           choices=['v1', 'v2'],
                           default='v1',
                           type=str,
                           help='The KV Version (v1, v2) Default: "v1"')
        param.add_argument("-v", "--verbose",
                           help="Verbose logs",
                           const=True,
                           nargs="?")

    return parser


class Envs:
    def __init__(self, args):
        self.args = args

    def get_envs(self):

        if "EDITOR" in os.environ:
            editor=os.environ["EDITOR"]
            if self.args.verbose is True:
                print("The env editor is: " + editor)
        else:
            try:
                editor = self.args.edit
                if self.args.verbose is True:
                    print("The editor is: " + editor)
            except AttributeError:
                if platform.system() != "Windows":
                    editor = "vi"
                    if self.args.verbose is True:
                        print("The default editor is: " + editor)
                else:
                    editor = "notepad"
                    if self.args.verbose is True:
                        print("The default editor is: " + editor)
            except Exception as ex:
                print(f"Error: {ex}")

        if "KVVERSION" in os.environ:
            kvversion=os.environ["KVVERSION"]
            if self.args.verbose is True:
                print("The env kvversion is: " + kvversion)
        else:
            if self.args.kvversion:
                kvversion = self.args.kvversion
                if self.args.verbose is True:
                    print("The kvversion is: " + kvversion)
            else:
                kvversion = "v1"
                if self.args.verbose is True:
                    print("The default kvversion is: " + kvversion)

        return editor, kvversion


class Vault:
    def __init__(self, args, envs):
        self.args = args
        self.envs = envs
        self.kvversion = envs[1]

        # Setup Vault client (hvac)
        try:
            self.client = hvac.Client(url=os.environ["VAULT_ADDR"],
                                      token=os.environ["VAULT_TOKEN"])
        except KeyError:
            print(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            print(f"ERROR: {ex}")
            sys.exit(1)

        if self.kvversion == "v1":
            self.secret_client = self.client.secrets.kv.v1
        elif self.kvversion == "v2":
            self.secret_client = self.client.secrets.kv.v2
        else:
            print("Wrong KV Version specified, either v1 or v2")
            sys.exit(1)

    def get_path_and_key(self, path):
        key = path.split('/')[-1]
        mount_point = path.split('/')[0]
        path = "/".join(path.split('/')[1:-1])
        return mount_point, path, key

    def vault_write(self, value, path):
        mount_point, path, key = self.get_path_and_key(path)
        try:
            self.secret_client.create_or_update_secret(
                path=f"{path}",
                secret={key: value},
                mount_point=mount_point
            )
            if self.args.verbose is True:
                print(f"Wrote '{value}' to: {mount_point}{path}/{key}")
        except AttributeError:
            print(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            print(f"Error: {ex}")

    def vault_read(self, value, path):
        mount_point, path, key = self.get_path_and_key(path)

        try:
            value = self.secret_client.read_secret(
                path=path,
                mount_point=mount_point
            )
            if 'data' not in value:
                raise Exception("Cannot find path or read secret")
            elif key not in value['data']:
                raise Exception(f"Cannot find key '{key}' in secret's path")
            secret = value.get("data", {}).get(key)
            if self.args.verbose is True:
                print(f"Got '{secret}' from: {mount_point}{path}{key}")
            return secret
        except AttributeError:
            print(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            print(f"Error: {ex}")
        except Exception as ex:
            print(f"ERROR: {ex}")


def load_yaml(yaml_file):
    # Load the YAML file
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    with open(yaml_file) as filepath:
        data = yaml.load(filepath)
        return data


def cleanup(args):
    # Cleanup decrypted files
    yaml_file = args.yaml_file
    try:
        os.remove(f"{yaml_file}.dec")
        if args.verbose is True:
            print(f"Deleted {yaml_file}.dec")
            sys.exit()
    except AttributeError:
        for fl in glob.glob("*.dec"):
            os.remove(fl)
            if args.verbose is True:
                print(f"Deleted {fl}")
                sys.exit()
    except Exception as ex:
        print(f"Error: {ex}")
    else:
        sys.exit()

# Get value from a nested hash structure given a path of key names
# For example:
# secret_data['mysql']['password'] = "secret"
# value_from_path(secret_data, "/mysql/password") => returns "secret"
def value_from_secret_data(secret_data, path):
    val = secret_data
    for key in path.split('/'):
        if not key:
            continue
        if key in val.keys():
            val = val[key]
        else:
            raise Exception(f"Missing secret value. Key {key} does not exist when retrieving value for '{path}'")
    return val


def lookup_key_val(pos, caller, key, i=0):
    for l in caller.split('.')[i:]:
        if l not in pos:
            print(f"Warning: cannot find '{l}' in the .yaml.dec file! Input manually or Ctrl-c to exit.")
            return None
        if key in pos[l]:
            return pos[l][key]
        return lookup_key_val(pos[l], caller, key, i+1)


def get_input(path):
    return getpass.getpass(f"Input a value for '{path}': ")


def dict_walker(data, args, envs, secret_data, path=None, caller=None):

    # Walk through the loaded dicts looking for the values we want
    path = path if path is not None else ""
    action = args.action
    if isinstance(data, dict):
        for key, value in data.items():
            if m := re.match(r'vault_secret\([\'"](.*?)[\'"]\)', str(value)):
                path = m.group(1)

                if args.verbose is True:
                    print(f"Found key/value to process: {key}={value}")

                if action == "enc":
                    if secret_data:
                        if caller is None:
                            data[key] = secret_data[key]
                        else:
                            data[key] = lookup_key_val(secret_data, caller, key)
                        if data[key] is None:
                            data[key] = get_input(path)

                        if args.verbose is True:
                            print(f"Key to write at {value}: '%s'" % data[key])
                    else:
                        data[key] = get_input(path)
              #      vault = Vault(args, envs)
              #      vault.vault_write(data[key], path)
              #  elif action in COMMANDS ^ {'enc', 'clean'}:
              #      vault = Vault(args, envs)
              #      vault = vault.vault_read(value, path)
              #      value = vault
              #      data[key] = value
            if caller is not None:
                key = caller + '.' + key
            for res in dict_walker(value, args, envs, secret_data, path=f"{path}", caller=key):
                yield res
    #elif isinstance(data, list):
    #    for item in data:
    #        for res in dict_walker(item, args, envs, secret_data, path=f"{path}"):
    #            yield res


def load_secret(args): 
    if args.secret_file:
        if not re.search(r'\.yaml\.dec$', args.secret_file):
            raise Exception(f"ERROR: Secret file name must end with \".yaml.dec\". {args.secret_file} was given instead.")
        return load_yaml(args.secret_file)


def main(argv=None):

    # Parse arguments from argparse
    # This is outside of the parse_arg function because of issues returning multiple named values from a function
    parsed = parse_args(argv)
    args, leftovers = parsed.parse_known_args(argv)

    yaml_file = args.yaml_file
    data = load_yaml(yaml_file)
    action = args.action

    if action == "clean":
        cleanup(args)

    envs = Envs(args)
    envs = envs.get_envs()
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    secret_data = load_secret(args) if args.action == 'enc' else None

    for path, key, value in dict_walker(data, args, envs, secret_data):
        print("Done")

    if action == "dec":
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        print("Done Decrypting")
    elif action == "view":
        yaml.dump(data, sys.stdout)
    elif action == "edit":
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        os.system(envs[0] + ' ' + f"{yaml_file}.dec")
    # These Helm commands are only different due to passed variables
    elif action in COMMANDS ^ {'enc', 'edit', 'dec', 'view', 'clean'}:
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        leftovers = ' '.join(leftovers)

        try:
            subprocess.run(f"helm {args.action} {leftovers} -f {yaml_file}.dec", shell=True)
        except Exception as ex:
            print(f"Error: {ex}")

        cleanup(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"ERROR: {ex}")
        sys.exit(1)
    except SystemExit:
        pass
