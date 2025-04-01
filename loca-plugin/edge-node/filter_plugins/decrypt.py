#!/usr/bin/python
# coding=utf-8

#------------------------------------------------------------------
# Lenovo Open Cloud Automation
#------------------------------------------------------------------
# Copyright 2022 Lenovo. All rights reserved.
# License: Subject to terms of Lenovo License Agreement found in /opt/lenovo/license
# Author: Lenovo 
#------------------------------------------------------------------
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret



def decrypt(value, vault_pass):
    vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(vault_pass.encode()))])
    
    return vault.decrypt(value).decode('utf-8')

class FilterModule(object):
    def filters(self):
        return {
            'decrypt': decrypt
        }

