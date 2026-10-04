from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.store import Store
from vulnforge.engine.orchestrator import ScanConfig, run_scan



def test_authorization_negative_control_is_recorded_and_passes(
    mock_server,
    tmp_path,
):
    auth = AuthorizationContext(
        allowed_hosts=["127.0.0.1"],
        profile_name="lab",
        allow_private=True,
        confirmed=True,
    )

    auth_data = {
        "identities": {
            "owner": {
                "headers": {"X-Lab-User": "alice"},
            },
            "other": {
                "headers": {"X-Lab-User": "bob"},
            },
        },
        "authorization_tests": [
            {
                "url": "/authz/orders?id=1",
                "owner_identity": "owner",
                "other_identity": "other",
                "owner_field": "owner",
                "owner_value": "alice",
                "identity_assertion": {
                    "header": "X-Lab-Principal",
                    "owner_value": "alice",
                    "other_value": "bob",
                },
                "sensitive_fields": ["email"],
                "negative_control": {
                    "url": "/authz/protected-orders",
                    "expected_status": 403,
                },
            }
        ],
    }

    cfg = ScanConfig(
        target=mock_server,
        profile_name="lab",
        allowed_hosts=["127.0.0.1"],
        allow_private=True,
        authorization_confirmed=True,
        active_requested=True,
        auth_data=auth_data,
        test_profile="critical",
    )

    result = run_scan(cfg, auth)

    records = result.context.tests
    assert records

    record = records[0]

    assert record["negative_control_configured"] is True
    assert record["negative_control_status"] == 403
    assert record["negative_control_denied"] is True
    assert record["negative_control_resource_absent"] is True
    assert record["negative_control_ok"] is True
    assert record["negative_control_exchange_id"]
    assert record["negative_control_exchange_id"] in record["exchange_ids"]


def test_explicit_cross_account_test_verifies_and_redacts(mock_server,tmp_path):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="lab",allow_private=True,confirmed=True)
    auth_data={"identities":{"owner":{"headers":{"X-Lab-User":"alice"}},
                              "other":{"headers":{"X-Lab-User":"bob"}}},
        "authorization_tests":[{"url":"/authz/orders?id=1","owner_identity":"owner",
          "other_identity":"other","owner_field":"owner","owner_value":"alice",
          "identity_assertion":{"header":"X-Lab-Principal","owner_value":"alice","other_value":"bob"},
          "sensitive_fields":["email"]}]}
    cfg=ScanConfig(target=mock_server,profile_name="lab",allowed_hosts=["127.0.0.1"],allow_private=True,
       authorization_confirmed=True,active_requested=True,auth_data=auth_data,test_profile="critical")
    result=run_scan(cfg,auth)
    verified=[f for f in result.context.verified_findings if f.status=="VERIFIED"]
    assert len(verified)==1
    assert verified[0].category=="authorization / BOLA"
    assert verified[0].state=="VERIFIED"
    assert "alice@example.test" not in str(verified[0].to_dict())
    assert result.context.tests[0]["status"]=="VERIFIED"
    assert next(h for h in result.context.hypotheses if h.category=="object-level-authorization").status=="VERIFIED"
    phases={p.phase_id:p.status for p in result.context.phases}
    assert phases["phase-10"]=="PARTIAL" and phases["phase-11"]=="PARTIAL"
    assert phases["phase-13"]=="COMPLETE" and phases["phase-14"]=="COMPLETE"
    store=Store(str(tmp_path/"verify.db")); store.save_scan(result)
    chain=store.get_evidence_chain(verified[0].id)
    assert chain and chain[0]["test"]["status"]=="VERIFIED"
    assert chain[0]["test"]["hypothesis_id"]==verified[0].evidence[0].detail["hypothesis_id"]
    doc=store.get_report(result.context.scan_id)
    assert len(doc["phases"])==15 and doc["phases"][9]["status"]=="PARTIAL"
    assert doc["test_plan"][0]["status"]=="EXECUTED"
    assert doc["scan"]["test_profile"]=="critical"
    bola=next(row for row in doc["vulnerability_matrix"] if row["class_id"]=="bola")
    ssrf_row=next(row for row in doc["vulnerability_matrix"] if row["class_id"]=="ssrf")
    assert bola["selected"] and bola["status"]=="CONFIRMED" and bola["executed"]==1
    assert ssrf_row["selected"] and ssrf_row["supported"] is True and ssrf_row["status"] in {"TESTED_CLEAN","OBSERVATION_ONLY","NO_TEST_SURFACE"}
    assert doc["security_properties"] and doc["actors"] and doc["resources"]
    assert doc["application_model"] and doc["risk_summary"]["verified_total"]==1
    assert len(doc["findings"])==1 and doc["findings"][0]["status"]=="VERIFIED"
    assert doc["report_manifest"]["verified_finding_ids"]==[verified[0].id]
    assert doc["asset_nodes"] and next(h for h in doc["hypotheses"] if h["category"]=="object-level-authorization")["status"]=="VERIFIED"
    assert len(chain[0]["exchanges"]) == 3
    assert all("alice@example.test" not in str(x) for x in chain[0]["exchanges"])
    import sqlite3
    con=sqlite3.connect(tmp_path/"verify.db")
    raw=" ".join(r[0] for r in con.execute("select data_json from exchanges where url like '%/authz/orders%'"))
    assert "alice@example.test" not in raw and '"x-lab-user":"alice"' not in raw


def test_authorization_plan_is_blocked_without_explicit_active_mode(mock_server):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="lab",allow_private=True,confirmed=True)
    auth_data={"identities":{"owner":{"headers":{"X-Lab-User":"alice"}},
                              "other":{"headers":{"X-Lab-User":"bob"}}},
        "authorization_tests":[{"url":"/authz/orders?id=1","owner_identity":"owner",
          "other_identity":"other","owner_field":"owner","owner_value":"alice",
          "identity_assertion":{"header":"X-Lab-Principal","owner_value":"alice","other_value":"bob"},
          "sensitive_fields":["email"]}]}
    cfg=ScanConfig(target=mock_server,profile_name="lab",allowed_hosts=["127.0.0.1"],allow_private=True,
       authorization_confirmed=True,active_requested=False,auth_data=auth_data)
    result=run_scan(cfg,auth)
    assert not result.context.tests
    assert result.context.test_plan
    assert all(plan.status=="BLOCKED" for plan in result.context.test_plan)
    assert any(plan.test_type=="cross-account-object-authorization" for plan in result.context.test_plan)
    assert any(plan.test_type=="sql-injection-validation" for plan in result.context.test_plan)
    authz=next(x for x in result.context.coverage if x["category"]=="Object-level authorization")
    assert authz["status"]=="BLOCKED"
    assert not result.context.verified_findings
    assert all(f.status!="VERIFIED" for f in result.context.findings)


def test_authorization_identities_expand_into_independent_matrix_entries():
    from vulnforge.engine.verification import expand_authorization_specs

    auth_data = {
        "authorization_tests": [
            {
                "url": "/authz/orders?id=1",
                "owner_identity": "owner",
                "identities": [
                    "other",
                    "admin",
                    "support",
                ],
                "identity_assertion": {
                    "header": "X-Lab-Principal",
                    "owner_value": "alice",
                    "other_values": {
                        "other": "bob",
                        "admin": "admin",
                        "support": "support",
                    },
                },
            }
        ]
    }

    expanded = expand_authorization_specs(auth_data)

    assert len(expanded) == 3

    assert [item["other_identity"] for item in expanded] == [
        "other",
        "admin",
        "support",
    ]

    assert [
        item["identity_assertion"]["other_value"]
        for item in expanded
    ] == [
        "bob",
        "admin",
        "support",
    ]

    assert [
        item["authorization_matrix"]["owner_identity"]
        for item in expanded
    ] == [
        "owner",
        "owner",
        "owner",
    ]




def test_authorization_object_identity_matrix_expands_cartesian_cells():
    from vulnforge.engine.verification import expand_authorization_specs

    auth_data = {
        "authorization_tests": [
            {
                "owner_identity": "owner",
                "identities": ["user", "admin", "support"],
                "objects": [
                    {
                        "name": "alice-order",
                        "url": "/authz/orders?id=1",
                        "owner": "alice",
                        "expected": {
                            "user": "DENY",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                    {
                        "name": "bob-order",
                        "url": "/authz/orders?id=2",
                        "owner": "bob",
                        "expected": {
                            "user": "ALLOW",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                ],
            }
        ]
    }

    expanded = expand_authorization_specs(auth_data)

    assert len(expanded) == 6

    cells = {
        (
            item["authorization_matrix"]["object_name"],
            item["authorization_matrix"]["other_identity"],
        ): item
        for item in expanded
    }

    assert set(cells) == {
        ("alice-order", "user"),
        ("alice-order", "admin"),
        ("alice-order", "support"),
        ("bob-order", "user"),
        ("bob-order", "admin"),
        ("bob-order", "support"),
    }

    assert cells[("alice-order", "user")]["expected_decision"] == "DENY"
    assert cells[("alice-order", "admin")]["expected_decision"] == "ALLOW"
    assert cells[("alice-order", "support")]["expected_decision"] == "DENY"

    assert cells[("bob-order", "user")]["expected_decision"] == "ALLOW"
    assert cells[("bob-order", "admin")]["expected_decision"] == "ALLOW"
    assert cells[("bob-order", "support")]["expected_decision"] == "DENY"

    assert cells[("alice-order", "user")]["url"] == "/authz/orders?id=1"
    assert cells[("bob-order", "user")]["url"] == "/authz/orders?id=2"

    assert cells[("alice-order", "user")]["owner_value"] == "alice"
    assert cells[("bob-order", "user")]["owner_value"] == "bob"

    for item in expanded:
        assert item["owner_identity"] == "owner"
        assert item["other_identity"] in {"user", "admin", "support"}
        assert item["authorization_matrix"]["expected_decision"] in {
            "ALLOW",
            "DENY",
        }



def test_authorization_object_matrix_creates_independent_plans(
    mock_server,
):
    auth = AuthorizationContext(
        allowed_hosts=["127.0.0.1"],
        profile_name="lab",
        allow_private=True,
        confirmed=True,
    )

    auth_data = {
        "identities": {
            "owner": {
                "headers": {"X-Lab-User": "alice"},
                "authentication_context_id": "ctx-alice",
            },
            "user": {
                "headers": {"X-Lab-User": "bob"},
                "authentication_context_id": "ctx-bob",
            },
            "admin": {
                "headers": {"X-Lab-User": "admin"},
                "authentication_context_id": "ctx-admin",
            },
            "support": {
                "headers": {"X-Lab-User": "support"},
                "authentication_context_id": "ctx-support",
            },
        },
        "authorization_tests": [
            {
                "owner_identity": "owner",
                "identities": ["user", "admin", "support"],
                "objects": [
                    {
                        "name": "alice-order",
                        "url": "/authz/orders?id=1",
                        "owner": "alice",
                        "expected": {
                            "user": "DENY",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                    {
                        "name": "bob-order",
                        "url": "/authz/orders?id=2",
                        "owner": "bob",
                        "expected": {
                            "user": "ALLOW",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                ],
            }
        ],
    }

    cfg = ScanConfig(
        target=mock_server,
        profile_name="lab",
        allowed_hosts=["127.0.0.1"],
        allow_private=True,
        authorization_confirmed=True,
        active_requested=True,
        auth_data=auth_data,
        test_profile="critical",
    )

    result = run_scan(cfg, auth)

    plans = [
        plan
        for plan in result.context.test_plan
        if plan.test_type == "cross-account-object-authorization"
    ]

    assert len(plans) == 6
    assert all(plan.request_cost == 3 for plan in plans)

    # Strategy selection is planning provenance only. It must not itself
    # create a finding or bypass the existing verification pipeline.
    assert all(
        plan.methodology["strategy"]["strategy_id"] == "authz.object_boundary"
        for plan in plans
    )
    assert all(
        plan.methodology["strategy_selection"]["status"] == "APPLICABLE"
        for plan in plans
    )
    assert all(
        "authorization decision" in plan.methodology["strategy"]["verification_contract"]
        for plan in plans
    )
    assert not result.context.findings or all(
        finding.status != "VERIFIED"
        for finding in result.context.findings
    )

    specs = getattr(result.context, "_authorization_test_specs", [])
    assert len(specs) == 6

    cells = {
        (
            spec["authorization_matrix"]["object_name"],
            spec["authorization_matrix"]["other_identity"],
        )
        for spec in specs
    }

    assert cells == {
        ("alice-order", "user"),
        ("alice-order", "admin"),
        ("alice-order", "support"),
        ("bob-order", "user"),
        ("bob-order", "admin"),
        ("bob-order", "support"),
    }

    assert len({plan.test_id for plan in plans}) == 6
    assert sum(plan.request_cost for plan in plans) == 18


def test_multi_identity_authorization_matrix_executes_independent_tests(
    mock_server,
):
    auth = AuthorizationContext(
        allowed_hosts=["127.0.0.1"],
        profile_name="lab",
        allow_private=True,
        confirmed=True,
    )

    auth_data = {
        "identities": {
            "owner": {
                "headers": {"X-Lab-User": "alice"},
                "authentication_context_id": "ctx-alice",
            },
            "user": {
                "headers": {"X-Lab-User": "bob"},
                "authentication_context_id": "ctx-bob",
            },
            "admin": {
                "headers": {"X-Lab-User": "admin"},
                "authentication_context_id": "ctx-admin",
            },
            "support": {
                "headers": {"X-Lab-User": "support"},
                "authentication_context_id": "ctx-support",
            },
        },
        "authorization_tests": [
            {
                "url": "/authz/orders?id=1",
                "owner_identity": "owner",
                "identities": [
                    "user",
                    "admin",
                    "support",
                ],
                "owner_field": "owner",
                "owner_value": "alice",
                "identity_assertion": {
                    "header": "X-Lab-Principal",
                    "owner_value": "alice",
                    "other_values": {
                        "user": "bob",
                        "admin": "admin",
                        "support": "support",
                    },
                },
                "sensitive_fields": ["email"],
            }
        ],
    }

    cfg = ScanConfig(
        target=mock_server,
        profile_name="lab",
        allowed_hosts=["127.0.0.1"],
        allow_private=True,
        authorization_confirmed=True,
        active_requested=True,
        auth_data=auth_data,
        test_profile="critical",
    )

    result = run_scan(cfg, auth)

    # The scan has a global research ledger. Filter to the
    # authorization matrix rather than assuming authorization is
    # the only active test family.
    records = [
        record
        for record in result.context.tests
        if record.get("type")
        == "cross-account-object-authorization"
    ]

    assert len(records) == 3

    assert [
        record["authorization_matrix"]["other_identity"]
        for record in records
    ] == [
        "user",
        "admin",
        "support",
    ]

    assert [
        record["other_identity_label"]
        for record in records
    ] == [
        "user",
        "admin",
        "support",
    ]

    assert [
        record["authorization_matrix"]["owner_identity"]
        for record in records
    ] == [
        "owner",
        "owner",
        "owner",
    ]

    context_ids = {
        record["other_authentication_context_id"]
        for record in records
    }

    assert context_ids == {
        "ctx-bob",
        "ctx-admin",
        "ctx-support",
    }

    assert all(
        record["owner_authentication_context_id"]
        == "ctx-alice"
        for record in records
    )

    assert all(
        record["owner_authentication_context_id"]
        != record["other_authentication_context_id"]
        for record in records
    )

    assert all(
        record["status"] == "VERIFIED"
        for record in records
    )

    exchange_sets = [
        set(record["exchange_ids"])
        for record in records
    ]

    assert all(exchange_sets)
    assert len(set.union(*exchange_sets)) == sum(
        len(values)
        for values in exchange_sets
    )


def test_authorization_decision_deny_with_access_is_boundary_violation():
    from vulnforge.engine.verification import _evaluate_authorization_decision

    result = _evaluate_authorization_decision(
        expected_decision="DENY",
        access_observed=True,
        response_status=200,
    )

    assert result["expected_decision"] == "DENY"
    assert result["observed_decision"] == "ALLOW"
    assert result["decision_matches"] is False
    assert result["boundary_violation"] is True
    assert result["classification"] == "BOUNDARY_VIOLATION"


def test_authorization_decision_deny_without_access_is_expected():
    from vulnforge.engine.verification import _evaluate_authorization_decision

    result = _evaluate_authorization_decision(
        expected_decision="DENY",
        access_observed=False,
        response_status=403,
    )

    assert result["expected_decision"] == "DENY"
    assert result["observed_decision"] == "DENY"
    assert result["decision_matches"] is True
    assert result["boundary_violation"] is False
    assert result["classification"] == "EXPECTED"


def test_authorization_decision_allow_with_access_is_expected():
    from vulnforge.engine.verification import _evaluate_authorization_decision

    result = _evaluate_authorization_decision(
        expected_decision="ALLOW",
        access_observed=True,
        response_status=200,
    )

    assert result["expected_decision"] == "ALLOW"
    assert result["observed_decision"] == "ALLOW"
    assert result["decision_matches"] is True
    assert result["boundary_violation"] is False
    assert result["classification"] == "EXPECTED"


def test_authorization_decision_allow_without_access_is_policy_mismatch():
    from vulnforge.engine.verification import _evaluate_authorization_decision

    result = _evaluate_authorization_decision(
        expected_decision="ALLOW",
        access_observed=False,
        response_status=403,
    )

    assert result["expected_decision"] == "ALLOW"
    assert result["observed_decision"] == "DENY"
    assert result["decision_matches"] is False
    assert result["boundary_violation"] is False
    assert result["classification"] == "POLICY_MISMATCH"


def test_authorization_object_matrix_executes_and_classifies_all_cells(
    mock_server,
):
    auth = AuthorizationContext(
        allowed_hosts=["127.0.0.1"],
        profile_name="lab",
        allow_private=True,
        confirmed=True,
    )

    auth_data = {
        "identities": {
            "owner": {
                "headers": {"X-Lab-User": "alice"},
                "authentication_context_id": "ctx-alice",
            },
            "user": {
                "headers": {"X-Lab-User": "bob"},
                "authentication_context_id": "ctx-bob",
            },
            "admin": {
                "headers": {"X-Lab-User": "admin"},
                "authentication_context_id": "ctx-admin",
            },
            "support": {
                "headers": {"X-Lab-User": "support"},
                "authentication_context_id": "ctx-support",
            },
        },
        "authorization_tests": [
            {
                "owner_identity": "owner",
                "identities": [
                    "user",
                    "admin",
                    "support",
                ],
                "owner_field": "owner",
                "identity_assertion": {
                    "header": "X-Lab-Principal",
                    "owner_value": "alice",
                    "other_values": {
                        "user": "bob",
                        "admin": "admin",
                        "support": "support",
                    },
                },
                "sensitive_fields": ["email"],
                "objects": [
                    {
                        "name": "alice-order",
                        "url": "/authz/matrix-object?id=alice-1",
                        "owner": "alice",
                        "expected": {
                            "user": "DENY",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                    {
                        "name": "bob-order",
                        "url": "/authz/matrix-object?id=bob-1",
                        "owner": "bob",
                        "expected": {
                            "user": "ALLOW",
                            "admin": "ALLOW",
                            "support": "DENY",
                        },
                    },
                ],
            }
        ],
    }

    cfg = ScanConfig(
        target=mock_server,
        profile_name="lab",
        allowed_hosts=["127.0.0.1"],
        allow_private=True,
        authorization_confirmed=True,
        active_requested=True,
        auth_data=auth_data,
        test_profile="critical",
    )

    result = run_scan(cfg, auth)

    records = [
        record
        for record in result.context.tests
        if record.get("type")
        == "cross-account-object-authorization"
    ]

    assert len(records) == 6

    from urllib.parse import urlsplit

    by_cell = {
        (
            urlsplit(
                record["authorization_matrix"]["target_object"]
            ).path
            + (
                "?"
                + urlsplit(
                    record["authorization_matrix"]["target_object"]
                ).query
                if urlsplit(
                    record["authorization_matrix"]["target_object"]
                ).query
                else ""
            ),
            record["authorization_matrix"]["other_identity"],
        ): record
        for record in records
    }

    assert len(by_cell) == 6

    expected = {
        ("/authz/matrix-object?id=alice-1", "user"):
            "EXPECTED",
        ("/authz/matrix-object?id=alice-1", "admin"):
            "EXPECTED",
        ("/authz/matrix-object?id=alice-1", "support"):
            "EXPECTED",
        ("/authz/matrix-object?id=bob-1", "user"):
            "EXPECTED",
        ("/authz/matrix-object?id=bob-1", "admin"):
            "EXPECTED",
        ("/authz/matrix-object?id=bob-1", "support"):
            "EXPECTED",
    }

    for cell, classification in expected.items():
        record = by_cell[cell]

        print(
            "\nMATRIX CELL:",
            cell,
            "\n  expected:", classification,
            "\n  actual:", record["authorization_classification"],
            "\n  decision:", record["authorization_decision"],
            "\n  owner_verified:", record["owner_identity_verified"],
            "\n  other_verified:", record["other_identity_verified"],
            "\n  identity_separation:", record["identity_separation"],
            "\n  differential_ok:", record["differential_ok"],
            "\n  reproduction_ok:", record["reproduction_ok"],
            "\n  impact_ok:", record["impact_ok"],
        )

        assert (
            record["authorization_classification"]
            == classification
        )

        assert (
            record["authorization_decision"][
                "classification"
            ]
            == classification
        )

        assert record["authorization_boundary_violation"] is (
            classification == "BOUNDARY_VIOLATION"
        )

        assert record["baseline_exchange_id"]
        assert record["cross_account_exchange_id"]
        assert record["repeat_exchange_id"]

    assert len({
        record["cross_account_exchange_id"]
        for record in records
    }) == 6
