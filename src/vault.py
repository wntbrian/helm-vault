#!/usr/bin/env python3
import os
import re
import sys
import hvac
import argparse

RawTextHelpFormatter = argparse.RawTextHelpFormatter
import glob
import getpass
import logging
import platform
import subprocess
import ruamel.yaml
import shlex
import base64

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
LOG = logging.getLogger(__name__)


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
    encrypt.add_argument("-s", "--secret-file", type=str,
                         help="File containing the secret for input. Must end in .yaml.dec")

    # Decrypt help
    decrypt = subparsers.add_parser("dec", help="Parse a YAML file and retrieve values from Vault")
    decrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")

    # Clean help
    clean = subparsers.add_parser("clean", help="Remove decrypted files (*.yaml.dec in the current directory)")
    clean.add_argument("-v", "--verbose", help="Verbose logs", const=True, nargs="?")

    # View Help
    view = subparsers.add_parser("view", help="View decrypted YAML file")
    view.add_argument("yaml_file", type=str, help="The YAML file to be worked on")

    # Edit Help
    edit = subparsers.add_parser("edit", help="Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.")
    edit.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    edit.add_argument("-e", "--editor", help='Editor name. Default: (Linux/MacOS) "vi" (Windows) "notepad"', const=True,
                      nargs="?")

    # Install Help
    install = subparsers.add_parser("install", help="Wrapper that decrypts YAML files before running helm install")
    install.add_argument("-f", "--values", type=str, dest="yaml_file",
                         help="The encrypted YAML file to decrypt on the fly")

    # Template Help
    template = subparsers.add_parser("template", help="Wrapper that decrypts YAML files before running helm template")
    template.add_argument("-f", "--values", default='values.yaml', type=str, dest="yaml_file",
                          help="The encrypted YAML file to decrypt on the fly")

    # Upgrade Help
    upgrade = subparsers.add_parser("upgrade", help="Wrapper that decrypts YAML files before running helm upgrade")
    upgrade.add_argument("-f", "--values", type=str, dest="yaml_file",
                         help="The encrypted YAML file to decrypt on the fly")

    # Lint Help
    lint = subparsers.add_parser("lint", help="Wrapper that decrypts YAML files before running helm link")
    lint.add_argument("-f", "--values", type=str, dest="yaml_file",
                      help="The encrypted YAML file to decrypt on the fly")

    # Diff Help
    diff = subparsers.add_parser("diff", help="Wrapper that decrypts YAML files before running helm diff")
    diff.add_argument("-f", "--values", type=str, dest="yaml_file",
                      help="The encrypted YAML file to decrypt on the fly")

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
        param.add_argument("-x", "--helm-bin",
                           help="Helm's binary path. Default %(default)s",
                           default="/usr/local/bin/helm",
                           type=str)
        param.add_argument("-p", "--set",
                           action='append',
                           help="Helm's overrides",
                           type=str)
    return parser


def set_logger(verbose):
    fh = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    fh.setFormatter(formatter)
    LOG.addHandler(fh)

    if verbose is True:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.ERROR)


class Envs:
    def __init__(self, args):
        self.args = args

    def get_envs(self):

        if "EDITOR" in os.environ:
            editor = os.environ["EDITOR"]
        else:
            try:
                editor = self.args.edit
            except AttributeError:
                if platform.system() != "Windows":
                    editor = "vi"
                else:
                    editor = "notepad"
            except Exception as ex:
                LOG.error(f"{ex}")
                sys.exit(1)

        LOG.debug("The env editor is: " + editor)

        if "KVVERSION" in os.environ:
            kvversion = os.environ["KVVERSION"]
        else:
            if self.args.kvversion:
                kvversion = self.args.kvversion
            else:
                kvversion = "v1"

        LOG.debug("The kvversion is: " + kvversion)
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
            LOG.fatal(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            LOG.error(f"{ex}")
            sys.exit(1)

        if self.kvversion == "v1":
            self.secret_client = self.client.secrets.kv.v1
        elif self.kvversion == "v2":
            self.secret_client = self.client.secrets.kv.v2
        else:
            LOG.error("Wrong KV Version specified, either v1 or v2")
            sys.exit(1)

    def get_path_and_key(self, path):
        key = path.split('/')[-1]
        mount_point = path.split('/')[0]
        path = "/".join(path.split('/')[1:-1])
        return mount_point, path, key

    def vault_write(self, value, path):
        mount_point, path, key = self.get_path_and_key(path)
        payload = {}
        data = None
        # TODO: support kv_v2 patch: https://github.com/hvac/hvac/blob/develop/hvac/api/secrets_engines/kv_v2.py#L124
        # https://hvac.readthedocs.io/en/stable/usage/secrets_engines/kv_v2.html#patch-existing-secret
        # There seems to be no "PATCH" in kv_v1: https://github.com/hvac/hvac/blob/develop/hvac/api/secrets_engines/kv_v1.py
        # This means that just writing to an existing location will overwrite any other existing fields.
        # Therefore, have to work around this and first read the current data in order to re-commit it.
        # Possibly for kv_v2 the same has to be done because the PATCH method assumes the secret already exists else it
        # throws a `hvac.exceptions.InvalidPath` exception. Hence why for now both versions are evaluated here below:
        if self.kvversion == "v1" or self.kvversion == "v2":
            try:
                data = self.secret_client.read_secret(
                    path=path,
                    mount_point=mount_point
                )
            except hvac.exceptions.InvalidPath:
                pass
            except AttributeError:
                LOG.error(CONFIG_ERR_MSG)
                sys.exit(1)
            except Exception as ex:
                LOG.error(f"{ex}")
                sys.exit(1)

        if data is not None and 'data' in data:
            payload = data['data']

        payload[key] = value
        LOG.debug(f"Payload to send to Vault API: {payload}")
        try:
            self.secret_client.create_or_update_secret(
                path=f"{path}",
                secret=payload,
                mount_point=mount_point
            )
            LOG.debug(f"Wrote '{value}' to: {mount_point}/{path}/{key}")
        except AttributeError:
            LOG.error(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            LOG.error(f"{ex}")
            sys.exit(1)

    def vault_read(self, value, path):
        mount_point, path, key = self.get_path_and_key(path)

        try:
            value = self.secret_client.read_secret(
                path=path,
                mount_point=mount_point
            )
            if 'data' not in value:
                LOG.error("Cannot find path or read secret")
                sys.exit(1)
            elif key not in value['data']:
                LOG.error(f"Cannot find key '{key}' in secret's path")
                sys.exit(1)
            secret = value.get("data", {}).get(key)
            LOG.debug(f"Got '{secret}' from: {mount_point}/{path}{key}")
            return secret
        except AttributeError:
            LOG.error(CONFIG_ERR_MSG)
            sys.exit(1)
        except Exception as ex:
            LOG.error(f"{ex}")
            sys.exit(1)

    def vault_walk(self, path):
        mount_point, path, key = self.get_path_and_key(path)
        path += "/"+key

        try:
            read_secret_result = self.secret_client.read_secret(
                path=path,
                mount_point=mount_point,
            )
            LOG.debug(f"Got 'secrets from: {mount_point}/{path}{key}")
            return read_secret_result['data']
        except AttributeError:
            LOG.error(CONFIG_ERR_MSG)
            return None
        except Exception as ex:
            LOG.error(f"{ex}")
            return None


def load_yaml(yaml_file):
    # Load the YAML file
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    with open(yaml_file) as filepath:
        data = yaml.load(filepath)
        return data


def cleanup(args):
    # Cleanup decrypted files
    if isinstance(args, str):
        yaml_file = args
        verb = False
    else:
        yaml_file = args.yaml_file + ".dec"
        verb = args.verbose
    try:
        os.remove(f"{yaml_file}")
        if verb is True:
            LOG.info(f"Deleted {yaml_file}")
    except AttributeError:
        for fl in glob.glob("*.dec"):
            os.remove(fl)
            if verb is True:
                LOG.info(f"Deleted {fl}")
    except Exception as ex:
        sys.stderr.write(f"Error deleting: {ex}\n")


def lookup_key_val(pos, caller, key, i=0):
    for l in caller.split('.')[i:]:
        if l not in pos:
            LOG.warning(f"Warning: cannot find '{l}' in the .yaml.dec file! Input manually or Ctrl-c to exit.")
            return None
        if key in pos[l]:
            return pos[l][key]
        return lookup_key_val(pos[l], caller, key, i + 1)


def get_input(path):
    return getpass.getpass(f"Input a value for '{path}': ")


def add_branch(tree, vector, value):
    key = vector[0]
    if len(vector) == 1:
        tree[key] = value
    else:
        tree[key] = add_branch(tree[key] if key in tree else {}, vector[1:], value)
    return tree


def dict_walker(data, args, envs, secret_data, path=None, caller=None):
    # Walk through the loaded dicts looking for the values we want
    path = path if path is not None else ""
    action = args.action
    if isinstance(data, dict):
        for key, value in data.items():
            m = re.match(r'vault_secret_(.*?)_$', str(value))
            if m:
                path = m.group(1)

                LOG.debug(f"Found key/value to process: {key}={value}")

                if action == "enc":
                    if secret_data:
                        if caller is None:
                            data[key] = secret_data[key]
                        else:
                            data[key] = lookup_key_val(secret_data, caller, key)
                        if data[key] is None:
                            data[key] = get_input(path)

                        LOG.debug(f"Key to write at {value}: '%s'" % data[key])
                    else:
                        data[key] = get_input(path)
                    vault = Vault(args, envs)
                    vault.vault_write(data[key], path)
                elif action in COMMANDS ^ {'enc', 'clean'}:
                    vault = Vault(args, envs)
                    vault = vault.vault_read(value, path)
                    value = vault
                    data[key] = value
            if caller is not None:
                key = caller + '.' + key
            for res in dict_walker(value, args, envs, secret_data, path=f"{path}", caller=key):
                yield res
    elif isinstance(data, list):
        for item in data:
            for res in dict_walker(item, args, envs, secret_data, path=f"{path}"):
                yield res


def args_walker(args, envs, args_dict):
    action = args.action
    if isinstance(args.set, list):
        for i in range(len(args.set)):
            key, value = args.set[i].split('=', 1)
            splited_key = key.split('.')
            m = re.match(r'vault_secret_(.*?)_$', str(value))
            if m:
                path = m.group(1)

                LOG.debug(f"Found key/value to process: {key}={value}")

                if action in COMMANDS ^ {'enc', 'clean'}:
                    vault = Vault(args, envs)
                    vault = vault.vault_read(value, path)
                    value = vault
                    args_dict = add_branch(args_dict, splited_key, str(base64.b64encode(value.encode('utf-8')), 'utf-8'))
            else:
                if len(splited_key) > 1 and (splited_key[0] == "config" and splited_key[-1] != 'mount_path'):
                    args_dict = add_branch(args_dict, splited_key, str(base64.b64encode(value.encode('utf-8')), 'utf-8'))
                else:
                    args_dict = add_branch(args_dict, splited_key, value)

            yield i


def vault_walker(path, args, envs):
    vault = Vault(args, envs)
    vault_vars = vault.vault_walk(path)
    if vault_vars is not None:
        for key,value in vault_vars.items():
            vault_vars[key] = str(base64.b64encode(value.encode('utf-8')), 'utf-8')
    return vault_vars


def load_secret(args):
    if args.secret_file:
        if not re.search(r'\.yaml\.dec$', args.secret_file):
            LOG.fatal(f"ERROR: Secret file name must end with \".yaml.dec\". {args.secret_file} was given instead.")
            sys.exit(1)
        return load_yaml(args.secret_file)


def main(argv=None):
    # Parse arguments from argparse
    # This is outside of the parse_arg function because of issues returning multiple named values from a function
    parsed = parse_args(argv)
    args, leftovers = parsed.parse_known_args(argv)

    set_logger(args.verbose)

    action = args.action
    if action == "clean":
        cleanup(args)
        sys.exit()

    yaml_file = args.yaml_file
    data = load_yaml(yaml_file)

    envs = Envs(args)
    envs = envs.get_envs()
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    secret_data = load_secret(args) if args.action == 'enc' else None

    for _ in dict_walker(data, args, envs, secret_data):
        pass

    arg_dict = {}
    for _ in args_walker(args, envs, arg_dict):
        pass

    vault_dict = {'config': {'vault': {}}}
    if 'argocd_vault_path' in arg_dict and isinstance(arg_dict['argocd_vault_path'], str):
        vault_dict['config']['vault'] = vault_walker(arg_dict['argocd_vault_path'], args, envs)


    if action == "dec":
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        LOG.info("Done Decrypting")
    elif action == "view":
        yaml.dump(data, sys.stdout)
    elif action == "edit":
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        os.system(envs[0] + ' ' + f"{yaml_file}.dec")
    # These Helm commands are only different due to passed variables
    elif action in COMMANDS ^ {'enc', 'edit', 'dec', 'view', 'clean'}:
        yaml.dump(data, open(f"{yaml_file}.dec", "w"))
        leftovers = ' '.join(leftovers)

        arg_file = "args.yml"
        if (arg_dict):
            yaml.dump(arg_dict, open(f"{arg_file}", "w"))
            arg_file_cmd = f"-f {arg_file}"
        else:
            arg_file_cmd = ""

        vault_file = 'vault.yml'
        if vault_dict and vault_dict['config']['vault'] is not None:
            if 'config' in arg_dict:
                for _, arg_config in arg_dict['config'].items():
                    for key in arg_config:
                        if key in vault_dict['config']['vault']:
                            del(vault_dict['config']['vault'][key])
            vault_yml = ruamel.yaml.YAML()
            vault_yml.preserve_quotes = True
            vault_yml.indent(mapping=2)
            vault_yml.dump(vault_dict, open(vault_file, "w"))
            vault_file_cmd = f"-f {vault_file}"
        else:
            vault_file_cmd = ""

        command = f"{args.helm_bin} {args.action} {leftovers} -f {yaml_file}.dec {vault_file_cmd} {arg_file_cmd}"
        execute_com = shlex.split(command, posix=True)

        try:
            LOG.debug(execute_com)
            p = subprocess.Popen(execute_com)
            result  = p.communicate()
            #print(result)
            #subprocess.run(f"{args.helm_bin} {args.action} {helm_params} {leftovers} -f {yaml_file}.dec", shell=True)

        except Exception as ex:
            LOG.error(f"{ex}")
            sys.exit(1)
        else:
            LOG.info("Done, cleaning up...")

        cleanup(vault_file)
        cleanup(args)
        sys.exit()


if __name__ == "__main__":
    main()
