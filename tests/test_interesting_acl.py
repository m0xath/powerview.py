#!/usr/bin/env python3
"""Tests for Find-InterestingDomainAcl's ACE filtering.

The sweep is only useful if it throws away the inherited noise that makes up
almost every DACL in a domain while keeping the grants an operator cares
about, so the cases below pin both halves of that behaviour.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin

from powerview.modules.ldapattack import (
    ACCESS_MASK,
    RESET_PASSWORD_GUID,
    WRITE_MEMBERS_GUID,
    ACLEnum,
    is_nondefault_trustee,
)
from powerview.utils.accesscontrol import AccessControl

DOMAIN = "S-1-5-21-1004336348-1177238915-682003330"
HELPDESK = f"{DOMAIN}-1337"
DOMAIN_ADMINS = f"{DOMAIN}-512"
DOMAIN_USERS = f"{DOMAIN}-513"
AUTHENTICATED_USERS = "S-1-5-11"
SYSTEM = "S-1-5-18"


class FakePowerView:
    """Stands in for the resolution the real object does over LDAP."""

    def __init__(self):
        self.resolved = []

    def convertfrom_sid(self, sid):
        self.resolved.append(sid)
        return f"RESOLVED({sid})"


def plain_ace(sid, mask):
    return AccessControl.create_ace(sid, mask=mask)


def object_ace(sid, guid, mask=None):
    if mask is None:
        mask = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS

    ace = ldaptypes.ACE()
    ace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace['AceFlags'] = 0x00

    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['ObjectType'] = string_to_bin(guid)
    acedata['InheritedObjectType'] = b''
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    ace['Ace'] = acedata
    return ace


def entry(aces, dn="CN=target,DC=range,DC=local"):
    sd = AccessControl.create_empty_sd()
    sd['Dacl'].aces = list(aces)

    target_sid = ldaptypes.LDAP_SID()
    target_sid.fromCanonical(f"{DOMAIN}-1105")

    return {
        'dn': dn,
        'attributes': {
            'nTSecurityDescriptor': sd.getData(),
            'objectSid': target_sid.getData(),
            'distinguishedName': dn,
        },
    }


def sweep(aces, **kwargs):
    """Run the interesting-only enumeration and return the flattened ACEs."""
    powerview = FakePowerView()
    enum = ACLEnum(
        powerview,
        [entry(aces)],
        f"DC=range,DC=local",
        interesting_only=True,
        **kwargs
    )
    results = enum.read_dacl()
    flattened = [ace for result in results for ace in result['attributes']]
    return flattened, powerview


class TrusteeTests(unittest.TestCase):
    def test_rid_above_1000_is_reported(self):
        self.assertTrue(is_nondefault_trustee(HELPDESK))

    def test_builtin_principals_are_skipped(self):
        for sid in (DOMAIN_ADMINS, DOMAIN_USERS, SYSTEM, "S-1-5-32-544"):
            self.assertFalse(is_nondefault_trustee(sid), sid)

    def test_broad_principals_need_the_opt_in(self):
        for sid in (AUTHENTICATED_USERS, "S-1-1-0", DOMAIN_USERS):
            self.assertFalse(is_nondefault_trustee(sid), sid)
            self.assertTrue(is_nondefault_trustee(sid, include_broad=True), sid)

    def test_opt_in_does_not_pull_in_every_low_rid(self):
        """Domain Admins stays out even when broad trustees are requested."""
        self.assertFalse(is_nondefault_trustee(DOMAIN_ADMINS, include_broad=True))

    def test_empty_sid_is_not_interesting(self):
        self.assertFalse(is_nondefault_trustee(None))
        self.assertFalse(is_nondefault_trustee(""))

    def test_service_sids_are_not_mistaken_for_domain_principals(self):
        """PowerView's looser regex reports these purely for having a big RID."""
        service_sids = (
            "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
            "S-1-5-83-1-3166721032-1192260824-1234567890-1234567890",
            "S-1-5-90-0-2",
        )
        for sid in service_sids:
            self.assertFalse(is_nondefault_trustee(sid), sid)
            self.assertFalse(is_nondefault_trustee(sid, include_broad=True), sid)

    def test_trustees_from_another_domain_are_still_reported(self):
        foreign = "S-1-5-21-99999999-88888888-77777777-1104"
        self.assertTrue(is_nondefault_trustee(foreign))


class SweepTests(unittest.TestCase):
    def test_write_dacl_by_a_normal_principal_is_kept(self):
        found, _ = sweep([plain_ace(HELPDESK, ACCESS_MASK.WriteDACL.value)])
        self.assertEqual(len(found), 1)
        self.assertIn("WriteDACL", found[0]['ActiveDirectoryRights'])
        self.assertEqual(found[0]['SecurityIdentifier'], f"RESOLVED({HELPDESK})")

    def test_read_only_rights_are_dropped(self):
        found, _ = sweep([plain_ace(HELPDESK, ACCESS_MASK.ReadProperties.value
                                   | ACCESS_MASK.ReadControl.value)])
        self.assertEqual(found, [])

    def test_builtin_trustee_is_dropped_even_with_full_control(self):
        found, _ = sweep([plain_ace(DOMAIN_ADMINS, ACCESS_MASK.GenericAll.value)])
        self.assertEqual(found, [])

    def test_object_with_no_interesting_ace_disappears_entirely(self):
        powerview = FakePowerView()
        enum = ACLEnum(
            powerview,
            [entry([plain_ace(SYSTEM, ACCESS_MASK.GenericAll.value)])],
            "DC=range,DC=local",
            interesting_only=True,
        )
        self.assertEqual(enum.read_dacl(), [])

    def test_filtering_happens_before_sid_resolution(self):
        """The whole point of filtering early: no lookup for discarded ACEs."""
        _, powerview = sweep([
            plain_ace(SYSTEM, ACCESS_MASK.GenericAll.value),
            plain_ace(DOMAIN_ADMINS, ACCESS_MASK.GenericAll.value),
            plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value),
        ])
        self.assertEqual(powerview.resolved, [HELPDESK])

    def test_broad_trustee_opt_in_changes_the_result(self):
        aces = [plain_ace(AUTHENTICATED_USERS, ACCESS_MASK.GenericWrite.value)]

        found, _ = sweep(aces)
        self.assertEqual(found, [])

        found, _ = sweep(aces, include_broad_trustees=True)
        self.assertEqual(len(found), 1)

    def test_create_child_is_interesting(self):
        """OU-level CreateChild is what makes delegation abuse possible."""
        found, _ = sweep([object_ace(
            HELPDESK,
            RESET_PASSWORD_GUID,
            mask=ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD,
        )])
        self.assertEqual(len(found), 1)

    def test_delete_rights_are_interesting(self):
        """PowerView's rights match includes anything named Delete."""
        for mask in (ACCESS_MASK.Delete.value, ACCESS_MASK.DeleteTree.value):
            found, _ = sweep([plain_ace(HELPDESK, mask)])
            self.assertEqual(len(found), 1, hex(mask))

    def test_denied_extended_right_is_not_a_finding(self):
        denied = object_ace(HELPDESK, RESET_PASSWORD_GUID)
        denied['AceType'] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
        denied['TypeName'] = "ACCESS_DENIED_OBJECT_ACE"

        found, _ = sweep([denied])
        self.assertEqual(found, [])

        found, _ = sweep([object_ace(HELPDESK, RESET_PASSWORD_GUID)])
        self.assertEqual(len(found), 1)

    def test_without_the_flag_the_enum_is_unfiltered(self):
        """Get-DomainObjectAcl must keep behaving exactly as before."""
        powerview = FakePowerView()
        enum = ACLEnum(
            powerview,
            [entry([plain_ace(SYSTEM, ACCESS_MASK.ReadProperties.value)])],
            "DC=range,DC=local",
        )
        found = [ace for result in enum.read_dacl() for ace in result['attributes']]
        self.assertEqual(len(found), 1)


class ObjectAceDisplayTests(unittest.TestCase):
    """An object ACE must show every right it grants, not just the DS ones."""

    GROUP_CLASS = "bf967a9c-0de6-11d0-a285-00aa003049e2"

    def scoped_ace(self, mask):
        """Object ACE with no object type, limited to one inherited class."""
        ace = object_ace(HELPDESK, self.GROUP_CLASS, mask=mask)
        ace['Ace']['ObjectType'] = b''
        ace['Ace']['InheritedObjectType'] = string_to_bin(self.GROUP_CLASS)
        ace['Ace']['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT
        return ace

    def test_standard_rights_are_named(self):
        found, _ = sweep([self.scoped_ace(ACCESS_MASK.Delete.value | ACCESS_MASK.WriteDACL.value)])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['AccessMask'], "WriteDACL, Delete")

    def test_ds_rights_and_standard_rights_are_both_named(self):
        mask = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP | ACCESS_MASK.WriteOwner.value
        found, _ = sweep([self.scoped_ace(mask)])
        self.assertEqual(found[0]['AccessMask'], "WriteProperty, WriteOwner")

    def test_ds_only_ace_is_printed_as_before(self):
        mask = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD | ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
        found, _ = sweep([self.scoped_ace(mask)])
        self.assertEqual(found[0]['AccessMask'], "CreateChild, DeleteChild")

    def test_no_reported_ace_has_an_empty_rights_line(self):
        for mask in (ACCESS_MASK.Delete.value, ACCESS_MASK.DeleteTree.value,
                     ACCESS_MASK.WriteDACL.value, ACCESS_MASK.WriteOwner.value,
                     ACCESS_MASK.GenericAll.value, ACCESS_MASK.GenericWrite.value):
            found, _ = sweep([self.scoped_ace(mask)])
            self.assertEqual(len(found), 1, hex(mask))
            self.assertTrue(found[0]['AccessMask'], hex(mask))


class RightsFilterTests(unittest.TestCase):
    def test_resetpassword_keeps_only_that_extended_right(self):
        aces = [
            object_ace(HELPDESK, RESET_PASSWORD_GUID),
            object_ace(HELPDESK, WRITE_MEMBERS_GUID),
            plain_ace(HELPDESK, ACCESS_MASK.WriteDACL.value),
        ]
        found, _ = sweep(aces, rights_filter='ResetPassword')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['ObjectAceType'], 'User-Force-Change-Password')

    def test_writemembers_keeps_only_the_member_property(self):
        aces = [
            object_ace(HELPDESK, RESET_PASSWORD_GUID),
            object_ace(
                HELPDESK,
                WRITE_MEMBERS_GUID,
                mask=ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP,
            ),
        ]
        found, _ = sweep(aces, rights_filter='WriteMembers')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['ObjectAceType'], 'Member')

    def test_all_means_genericall(self):
        aces = [
            plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value),
            plain_ace(HELPDESK, ACCESS_MASK.WriteProperties.value),
        ]
        found, _ = sweep(aces, rights_filter='All')
        self.assertEqual(len(found), 1)
        self.assertIn("GenericAll", found[0]['ActiveDirectoryRights'])

    def test_all_matches_full_control_as_ad_stores_it(self):
        """A live DACL holds 0xF01FF, not the GENERIC_ALL bit."""
        aces = [
            plain_ace(HELPDESK, 0xF01FF),
            plain_ace(HELPDESK, 0xF01FF & ~ACCESS_MASK.WriteDACL.value),
        ]
        found, _ = sweep(aces, rights_filter='All')
        self.assertEqual(len(found), 1)
        self.assertIn("FullControl", found[0]['ActiveDirectoryRights'])

    def test_rights_filter_is_case_insensitive(self):
        aces = [plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)]
        for spelling in ('All', 'all', 'ALL'):
            found, _ = sweep(aces, rights_filter=spelling)
            self.assertEqual(len(found), 1, spelling)

    def test_unknown_filter_falls_back_to_any_modification_right(self):
        aces = [plain_ace(HELPDESK, ACCESS_MASK.WriteOwner.value)]
        found, _ = sweep(aces, rights_filter='NotARight')
        self.assertEqual(len(found), 1)


class _StubPagedSearch:
    @staticmethod
    def paged_search(*args, **kwargs):
        return []


class _StubStandard:
    standard = _StubPagedSearch()


class _StubSession:
    extend = _StubStandard()


class EndToEndTests(unittest.TestCase):
    """Drive the real method so the kwargs actually reach ACLEnum."""

    def build_powerview(self, aces):
        from powerview.powerview import PowerView

        pv = object.__new__(PowerView)
        pv.root_dn = "DC=range,DC=local"
        pv.configuration_dn = "CN=Configuration,DC=range,DC=local"
        pv.ldap_session = _StubSession()
        self.requested = {}

        def fake_get_domainobject(**kwargs):
            self.requested = kwargs
            return [entry(aces)]

        pv.get_domainobject = fake_get_domainobject
        pv.convertfrom_sid = lambda sid: f"RESOLVED({sid})"
        return pv

    def test_sweep_filters_through_the_public_method(self):
        pv = self.build_powerview([
            plain_ace(SYSTEM, ACCESS_MASK.GenericAll.value),
            plain_ace(HELPDESK, ACCESS_MASK.WriteDACL.value),
        ])

        results = pv.find_interestingdomainacl()
        found = [ace for result in results for ace in result['attributes']]

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['SecurityIdentifier'], f"RESOLVED({HELPDESK})")

    def test_searchbase_and_filter_reach_the_query(self):
        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])

        pv.find_interestingdomainacl(
            searchbase="OU=Servers,DC=range,DC=local",
            ldapfilter="(objectClass=organizationalUnit)",
        )

        self.assertEqual(self.requested['searchbase'], "OU=Servers,DC=range,DC=local")
        # the caller's filter is ANDed with the security-descriptor requirement
        self.assertIn("objectClass=organizationalUnit", self.requested['ldap_filter'])
        self.assertIn("nTSecurityDescriptor=*", self.requested['ldap_filter'])

    def test_rights_filter_reaches_the_enumerator(self):
        pv = self.build_powerview([
            plain_ace(HELPDESK, ACCESS_MASK.WriteDACL.value),
            plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value),
        ])

        results = pv.find_interestingdomainacl(rights_filter='All')
        found = [ace for result in results for ace in result['attributes']]

        self.assertEqual(len(found), 1)
        self.assertIn("GenericAll", found[0]['ActiveDirectoryRights'])

    def test_args_namespace_is_honoured(self):
        import argparse as _argparse

        pv = self.build_powerview([plain_ace(AUTHENTICATED_USERS, ACCESS_MASK.GenericWrite.value)])
        args = _argparse.Namespace(
            ldapfilter=None,
            searchbase=None,
            rights_filter=None,
            include_broad_trustees=True,
            resolveguids=True,
            no_cache=False,
            no_vuln_check=False,
            raw=False,
        )

        results = pv.find_interestingdomainacl(args=args)
        found = [ace for result in results for ace in result['attributes']]
        self.assertEqual(len(found), 1)

    def test_deleted_objects_are_left_out_by_default(self):
        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])
        pv.find_interestingdomainacl()
        self.assertFalse(self.requested['include_deleted'])
        self.assertFalse(self.requested['no_cache'])

    def test_tombstone_asks_for_deleted_objects(self):
        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])
        pv.find_interestingdomainacl(tombstone=True)
        self.assertTrue(self.requested['include_deleted'])

    def test_tombstone_search_never_touches_the_cache(self):
        """The cache key ignores LDAP controls, so a cached answer would be wrong."""
        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])
        pv.find_interestingdomainacl(tombstone=True, no_cache=False)
        self.assertTrue(self.requested['no_cache'])

    def test_tombstone_from_the_args_namespace(self):
        import argparse as _argparse

        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])
        pv.find_interestingdomainacl(args=_argparse.Namespace(tombstone=True))
        self.assertTrue(self.requested['include_deleted'])

    def test_get_domainobjectacl_still_works_without_args(self):
        """Regression guard for the uninitialised depth variable."""
        pv = self.build_powerview([plain_ace(HELPDESK, ACCESS_MASK.GenericAll.value)])
        results = pv.get_domainobjectacl(security_identifier=HELPDESK)
        self.assertEqual(len(results), 1)


class ParserTests(unittest.TestCase):
    def setUp(self):
        from powerview.utils.parsers import powerview_arg_parse
        self.parse = powerview_arg_parse

    def test_command_and_alias_both_parse(self):
        for command in ('Find-InterestingDomainAcl', 'Invoke-ACLScanner'):
            parsed = self.parse([command])
            self.assertIsNotNone(parsed, command)
            self.assertEqual(parsed.module.casefold(), command.casefold())

    def test_rights_filter_is_normalised(self):
        for spelling in ('resetpassword', 'ResetPassword', 'RESETPASSWORD'):
            parsed = self.parse(['Find-InterestingDomainAcl', '-RightsFilter', spelling])
            self.assertIsNotNone(parsed, spelling)
            self.assertEqual(parsed.rights_filter, 'ResetPassword', spelling)

    def test_rights_filter_rejects_junk(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(self.parse(['Find-InterestingDomainAcl', '-RightsFilter', 'nope']))

    def test_tombstone_flag_defaults_off(self):
        for command in ('Find-InterestingDomainAcl', 'Invoke-ACLScanner'):
            self.assertFalse(self.parse([command]).tombstone, command)
            self.assertTrue(self.parse([command, '-Tombstone']).tombstone, command)

    def test_broad_trustee_flag_defaults_off(self):
        parsed = self.parse(['Find-InterestingDomainAcl'])
        self.assertFalse(parsed.include_broad_trustees)
        parsed = self.parse(['Find-InterestingDomainAcl', '-IncludeBroadTrustees'])
        self.assertTrue(parsed.include_broad_trustees)


if __name__ == '__main__':
    unittest.main()
