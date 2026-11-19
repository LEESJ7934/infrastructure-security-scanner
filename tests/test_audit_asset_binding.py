import copy
import unittest
from asset_management.audit_binding import bind_audit_results

UID='9cd48a9c-bc17-4bbb-81ce-419f2bef8306'


class AuditAssetBindingTests(unittest.TestCase):
    def fixture(self):
        report={'origin':'SAVED_LAB','results':[{'asset_id':'linux-lab/one','checked_at':'2026-11-19T06:00:00+00:00','collected_at':'2026-11-01T06:00:00+00:00','status':'NEEDS_REVIEW'}]}
        bindings={'schema_version':1,'asset_namespace':'customer-a/vpc-a','bindings':{'linux-lab/one':UID}}
        return report,bindings

    def test_crosswalk_preserves_original_provenance_and_verdict_without_db_claim(self):
        report,bindings=self.fixture();before=copy.deepcopy(report)
        linked=bind_audit_results(report,bindings)
        row=linked['results'][0]
        self.assertEqual(row['asset_uid'],UID)
        self.assertEqual(row['asset_id'],row['source_asset_id'])
        self.assertEqual(row['collected_at'],before['results'][0]['collected_at'])
        self.assertEqual(row['status'],'NEEDS_REVIEW')
        self.assertEqual(row['asset_binding_verification'],'DECLARED_NOT_DB_VERIFIED')
        self.assertEqual(report,before)

    def test_same_uuid_in_distinct_namespace_is_explicit_and_not_merged_by_ip(self):
        report,bindings=self.fixture()
        a=bind_audit_results(report,bindings)
        b=bind_audit_results(report,{**bindings,'asset_namespace':'customer-b/vpc-b'})
        self.assertNotEqual(a['results'][0]['asset_namespace'],b['results'][0]['asset_namespace'])

    def test_missing_mapping_bad_namespace_and_ip_instead_of_uuid_rejected(self):
        report,bindings=self.fixture()
        for other in ({**bindings,'bindings':{}},{**bindings,'asset_namespace':'../ invalid'},
                      {**bindings,'bindings':{'linux-lab/one':'127.0.0.1'}},
                      {**bindings,'bindings':{'other':UID}}):
            with self.assertRaises(ValueError):bind_audit_results(report,other)


if __name__=='__main__':unittest.main()
