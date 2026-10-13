#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from unittest import mock

from impacket.examples import regsecrets, secretsdump
from impacket.smbconnection import SMBConnection


def newConnection():
    # No network: manualNegotiate skips the negotiation and the SMB layer is mocked
    connection = SMBConnection('target', '192.0.2.1', manualNegotiate=True)
    connection._SMBConnection = mock.Mock()
    return connection


class SMBConnectionLogoffCallbackTests(unittest.TestCase):

    def test_logoff_runs_callbacks_first_most_recent_first(self):
        connection = newConnection()
        calls = []
        connection._SMBConnection.logoff.side_effect = lambda: calls.append('logoff')
        connection.registerLogoffCallback(lambda: calls.append('first'))
        connection.registerLogoffCallback(lambda: calls.append('second'))
        connection.logoff()
        self.assertEqual(calls, ['second', 'first', 'logoff'])

    def test_failing_callback_does_not_prevent_logoff(self):
        connection = newConnection()
        connection.registerLogoffCallback(mock.Mock(side_effect=OSError('restore failed')))
        with self.assertLogs('impacket', level='ERROR'):
            connection.logoff()
        connection._SMBConnection.logoff.assert_called_once_with()

    def test_callbacks_run_once_and_can_be_unregistered(self):
        connection = newConnection()
        kept = mock.Mock()
        removed = mock.Mock()
        connection.registerLogoffCallback(kept)
        connection.registerLogoffCallback(kept)
        connection.registerLogoffCallback(removed)
        connection.unregisterLogoffCallback(removed)
        connection.logoff()
        connection.logoff()
        kept.assert_called_once_with()
        removed.assert_not_called()

    def test_close_runs_callbacks(self):
        connection = newConnection()
        callback = mock.Mock()
        connection.registerLogoffCallback(callback)
        connection.close()
        callback.assert_called_once_with()


class _RemoteOperationsLogoffCleanupTests:
    # Module holding the RemoteOperations class under test, set by the concrete test classes
    module = None

    def newRemoteOps(self, smbConnection):
        return self.module.RemoteOperations(smbConnection, False)

    def patchModule(self, name):
        return mock.patch('%s.%s' % (self.module.__name__, name))

    def setStoppedServiceState(self, remoteOps):
        # State left by enableRegistry() on a target where RemoteRegistry was stopped
        remoteOps._RemoteOperations__shouldStop = True
        remoteOps._RemoteOperations__serviceHandle = 'service-handle'

    def test_enable_registry_registers_finish_before_touching_the_target(self):
        smbConnection = mock.Mock()
        remoteOps = self.newRemoteOps(smbConnection)
        with self.patchModule('transport') as transport:
            transport.DCERPCTransportFactory.side_effect = OSError('connection refused')
            with self.assertRaises(OSError):
                remoteOps.enableRegistry()
        smbConnection.registerLogoffCallback.assert_called_once_with(remoteOps.finish)

    def test_finish_unregisters_even_when_it_fails(self):
        smbConnection = mock.Mock()
        remoteOps = self.newRemoteOps(smbConnection)
        self.setStoppedServiceState(remoteOps)
        with self.patchModule('scmr') as scmr:
            scmr.hRControlService.side_effect = OSError('restore failed')
            with self.assertRaises(OSError):
                remoteOps.finish()
        smbConnection.unregisterLogoffCallback.assert_called_once_with(remoteOps.finish)

    def test_close_restores_the_service_when_finish_is_never_called(self):
        connection = newConnection()
        remoteOps = self.newRemoteOps(connection)
        self.setStoppedServiceState(remoteOps)
        remoteOps._RemoteOperations__registerLogoffCleanup()
        with self.patchModule('scmr') as scmr:
            connection.close()
        scmr.hRControlService.assert_called_once()
        connection._SMBConnection.logoff.assert_called_once_with()

    def test_close_does_not_restore_again_after_an_explicit_finish(self):
        connection = newConnection()
        remoteOps = self.newRemoteOps(connection)
        self.setStoppedServiceState(remoteOps)
        remoteOps._RemoteOperations__registerLogoffCleanup()
        with self.patchModule('scmr') as scmr:
            remoteOps.finish()
            connection.close()
        scmr.hRControlService.assert_called_once()


class SecretsdumpLogoffCleanupTests(_RemoteOperationsLogoffCleanupTests, unittest.TestCase):
    module = secretsdump

    def test_remote_execution_registers_finish(self):
        smbConnection = mock.Mock()
        remoteOps = self.newRemoteOps(smbConnection)
        with mock.patch.object(remoteOps, '_RemoteOperations__smbExec'):
            remoteOps._RemoteOperations__executeRemote('whoami')
        smbConnection.registerLogoffCallback.assert_called_once_with(remoteOps.finish)


class RegsecretsLogoffCleanupTests(_RemoteOperationsLogoffCleanupTests, unittest.TestCase):
    module = regsecrets


if __name__ == '__main__':
    unittest.main(verbosity=1)
