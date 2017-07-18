#!/usr/bin/python
#
# Test Curl with GSSAPI authentication (KRB5)
#
# Copyright (C) 2016, Isaac Boukris <iboukris@gmail.com>
# MIT licensed - see COPYING
# Credit: Inspired by mod_auth_gssapi test suite by Simo Sorce <simo@redhat.com>
#
# Requires MIT krb5 packages, and python-gssapi.
# To run, change to tests/gssapi directory and run ./test_gssapi.py --path tmp


from kdc import KDC
import argparse
import os
import shutil
from string import Template
import subprocess
import sys


REALM = 'CURL.DEV'
ADDR = '127.0.0.1'
KDC_PORT = 8844
HTTP_PORT = 8040
HTTP_HOST = 'www.curl.dev'
USER_NAME = 'curluser'
USER_PWD = 'curlpwd'


def parse_args():
  parser = argparse.ArgumentParser(description='Curl GSSAPI Tests Environment')
  parser.add_argument('--path', default='%s/gssapi_tmp' % os.getcwd(),
                      help="Directory in which tests are run")

  return vars(parser.parse_args())


def run_httpd(addr, port, env, log):
  cmd = [os.path.join(os.getcwd(), 'httpd_negotiate.py'),
         '--addr', '%s' % addr, '--port', '%s' % port]
  with open(log, 'a') as logfile:
    httpdproc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=logfile,
                                 env=env, preexec_fn=os.setsid)

  ack = httpdproc.stdout.read(len('ready'));
  if ack != 'ready':
    httpdproc.terminate()
    raise Exception('Failed to start HTTPD server')

  return httpdproc


def kinit_user(user, pwd, env, log):
  with open(log, 'a') as logfile:
    kinit = subprocess.Popen(["kinit", '-V', user],
                             stdin=subprocess.PIPE,
                             stdout=logfile, stderr=logfile,
                             env=env, preexec_fn=os.setsid)
    kinit.communicate('%s\n' % pwd)
    kinit.wait()
    if kinit.returncode != 0:
      raise ValueError('kinit failed for user %s' % user)


def test_http_negotiate(kdc, testdir, log):
  keytab = os.path.join(testdir, 'http_service.keytab')
  kdc.add_service_principal('HTTP/%s' % HTTP_HOST, keytab)
  httpdenv = {'KRB5_KTNAME': keytab}
  httpdenv.update(kdc.env)
  httpdlog = os.path.join(testdir, 'httpd.log')
  httpdproc = run_httpd(ADDR, HTTP_PORT, httpdenv, httpdlog)

  try:
    kdc.add_user_principal(USER_NAME, USER_PWD)
    ccache = os.path.join(testdir, '%s.ccache' % USER_NAME)
    userenv = {'KRB5CCNAME': ccache}
    userenv.update(kdc.env)
    kinit_user(USER_NAME, USER_PWD, userenv, log)

    cmd = ['curl', '-v', '-s', '-u:', '--negotiate',
           '--resolve', '%s:%d:%s' % (HTTP_HOST, HTTP_PORT, ADDR),
           'http://%s:%d' % (HTTP_HOST, HTTP_PORT)]
    with open(log, 'a') as logfile:
      curl = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=logfile,
                              env=userenv, preexec_fn=os.setsid)
      user = curl.communicate()[0]

    if curl.returncode != 0:
      raise Exception('Curl command failed with %d!' % curl.returncode)

    if user != USER_NAME + '@' + REALM:
      raise Exception('HTTP Negotiate failed: wrong username returned!')

  finally:
    httpdproc.terminate()


if __name__ == '__main__':

  args = parse_args()

  testdir = args['path']
  if os.path.exists(testdir):
    shutil.rmtree(testdir)
  os.makedirs(testdir)

  testlog = os.path.join(testdir, 'tests.log')

  env = {'PATH': '../../src/.libs:' + os.environ['PATH'],
         'LD_LIBRARY_PATH': '../../lib/.libs'}

  try:
    kdc = KDC(REALM, env, testdir, ADDR, KDC_PORT)
    kdcproc = kdc.run()

    test_http_negotiate(kdc, testdir, testlog)
    sys.stderr.write('Curl GSSAPI: HTTP Negotiate test OK\n')

  finally:
    kdcproc.terminate()

