import json

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.engine.api_schema import parse_openapi_json
from vulnforge.engine.orchestrator import ScanConfig, run_scan


def test_openapi_parser_extracts_contract_fields_and_local_refs_without_values():
    document = {
        "openapi": "3.0.3",
        "components": {
            "parameters": {"OrderId": {"name": "order_id", "in": "path", "required": True,
                                         "schema": {"type": "integer"}, "example": "secret-example"}},
            "schemas": {"Order": {"type": "object", "properties": {"id": {"type": "integer"}}}},
        },
        "paths": {
            "/orders/{order_id}": {
                "parameters": [{"$ref": "#/components/parameters/OrderId"}],
                "get": {
                    "operationId": "readOrder",
                    "requestBody": {"$ref": "https://untrusted.example/schema.json"},
                    "responses": {"200": {"description": "ok", "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Order"}}
                    }}},
                },
            }
        },
    }
    parsed = parse_openapi_json(json.dumps(document), document_url="https://target.test/openapi.json", exchange_id="exchange-1")
    assert parsed["status"] == "PARSED"
    assert parsed["format"] == "OpenAPI 3.0.3"
    operation = parsed["operations"][0]
    assert operation["method"] == "GET" and operation["path"] == "/orders/{order_id}"
    assert operation["parameters"] == [{"name": "order_id", "in": "path", "required": True,
                                         "type": "integer", "source": "OpenAPI declaration"}]
    assert operation["response_content_types"] == ["application/json"]
    assert operation["validation_status"] == "DECLARED_NOT_VALIDATED"
    assert "secret-example" not in json.dumps(parsed)
    assert not operation["request_content_types"]


def test_swagger_2_parser_models_body_parameters_without_mutation():
    document = {"swagger":"2.0","consumes":["application/json"],"produces":["application/json"],
                "paths":{"/items":{"post":{"parameters":[{"name":"body","in":"body",
                "required":True,"schema":{"type":"object"}}],"responses":{"201":{"description":"created"}}}}}}
    parsed = parse_openapi_json(json.dumps(document), document_url="https://target.test/swagger.json")
    assert parsed["status"] == "PARSED" and parsed["format"] == "Swagger 2.0"
    operation = parsed["operations"][0]
    assert operation["parameters"][0]["in"] == "body"
    assert operation["parameters"][0]["type"] == "object"
    assert operation["request_content_types"] == ["application/json"]
    assert operation["response_content_types"] == ["application/json"]


def test_openapi_parser_rejects_yaml_and_unknown_versions_honestly():
    yaml_result = parse_openapi_json("openapi: 3.0.0\npaths: {}", document_url="https://target.test/openapi.yaml")
    assert yaml_result["status"] == "INVALID_OR_UNSUPPORTED"
    assert "YAML" in yaml_result["warnings"][0]
    unknown = parse_openapi_json('{"openapi":"4.0.0","paths":{}}', document_url="https://target.test/spec.json")
    assert unknown["status"] == "INVALID_OR_UNSUPPORTED"
    assert not unknown["operations"]


def test_scan_parses_only_linked_openapi_as_unvalidated_declarations(mock_server):
    authorization = AuthorizationContext(allowed_hosts=["127.0.0.1"], profile_name="passive",
                                         allow_private=True, confirmed=True)
    config = ScanConfig(target=mock_server, profile_name="passive", allowed_hosts=["127.0.0.1"],
                        allow_private=True, authorization_confirmed=True)
    result = run_scan(config, authorization)
    ctx = result.context
    docs = ctx.api_documents
    parsed_docs = [doc for doc in docs if doc["status"] == "PARSED"]
    blocked_docs = [doc for doc in docs if doc["status"] == "SCOPE_REJECTED"]
    assert len(parsed_docs) == 1 and len(blocked_docs) == 1
    assert parsed_docs[0]["source_exchange_id"]
    assert not any("out-of-scope.example" in exchange.url for exchange in ctx.requester.exchanges)
    assert not any(exchange.url.endswith("/openapi.yaml") for exchange in ctx.requester.exchanges)
    declared = [item for item in ctx.api_inventory if item.get("contract") == "DECLARED_NOT_VALIDATED"]
    assert len(declared) == 1
    assert declared[0]["path"] == "/api/orders/{order_id}"
    assert declared[0]["validation_status"] == "DECLARED_NOT_VALIDATED"
    assert not any("/api/orders/" in endpoint.url for endpoint in ctx.endpoints.values())
    assert any(exchange.module == "api-schema" for exchange in ctx.requester.exchanges)
