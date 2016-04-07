# Copyright (C) 2016, Isaac Boukris <iboukris@gmail.com>
# MIT licensed - see COPYING


import os
from string import Template
import subprocess


KRB5_CONF_TEMPLATE = '''
[libdefaults]
  default_realm = ${REALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  default_ccache_name = MEMORY:temp

[realms]
  ${REALM} = {
    kdc = ${ADDR}:${PORT}

    default_principal_flags = +preauth
    key_stash_file = ${DIR}/kdc_stash.file
  }

[domain_realm]
  .${LOWREALM} = ${REALM}
  ${LOWREALM} = ${REALM}

[dbmodules]
  ${REALM} = {
    database_name = ${DIR}/kdc_db.file
  }

[kdcdefaults]
 kdc_ports = ${PORT}
 kdc_tcp_ports = ${PORT}

[logging]
  kdc = FILE:${DIR}/kdc_log.file
'''

KEY_TYPE = "aes256-cts-hmac-sha1-96:normal"


class KDC:

  def __init__(self, realm, env, directory, addr, port):
    krb5conf = os.path.join(directory, 'krb5.conf')

    t = Template(KRB5_CONF_TEMPLATE)
    conf = t.substitute({'REALM': realm,
                         'DIR': directory,
                         'ADDR': addr,
                         'PORT': port,
                         'LOWREALM': realm.lower()})
    with open(krb5conf, 'w+') as f:
      f.write(conf)

    self.env = {}
    self.env.update(env)

    kdcenv = {'KRB5_CONFIG': krb5conf,
              'KRB5_TRACE': os.path.join(directory, 'krbtrace.log')}
    self.env.update(kdcenv)

    self.log = os.path.join(directory, 'kdc.log')

    with open(self.log, 'a') as logfile:
      ksetup = subprocess.Popen(["kdb5_util", "create", "-W", "-s",
                                 "-r", realm, "-P", "kdc-p@s$w0rd"],
                                stdout=logfile, stderr=logfile,
                                env=self.env, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
      raise ValueError('KDC Setup failed')


  def run(self):
    with open(self.log, 'a') as logfile:
      kdcproc = subprocess.Popen(['krb5kdc', '-n'],
                                 stdout=logfile, stderr=logfile,
                                 env=self.env, preexec_fn=os.setsid)

    return kdcproc


  def kadmin_local(self, cmd):
    with open(self.log, 'a') as logfile:
      kadmin = subprocess.Popen(["kadmin.local", "-q", cmd],
                              stdout=logfile, stderr=logfile,
                              env=self.env, preexec_fn=os.setsid)
    kadmin.wait()
    if kadmin.returncode != 0:
      raise ValueError('Kadmin local [%s] failed' % cmd)


  def add_user_principal(self, username, password):
    cmd = "addprinc -pw %s -e %s %s" % (password, KEY_TYPE, username)
    self.kadmin_local(cmd)


  def add_service_principal(self, service_name, keytab):
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, service_name)
    self.kadmin_local(cmd)

    cmd = "ktadd -k %s -e %s %s" % (keytab, KEY_TYPE, service_name)
    self.kadmin_local(cmd)

