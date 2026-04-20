curl -X POST "http://localhost:8000/api/devices" \
  -H "Authorization: Bearer test-token" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "filter_by": {
      "operation": "and",
      "operands": [
        {
          "field": "device_subcategory",
          "operation": "in",
          "value": ["Communication", "Process"]
        },
        {
          "field": "retired",
          "operation": "in",
          "value": [false]
        }
      ]
    },
    "offset": 0,
    "limit": 500,
    "fields": [
      "uid","asset_id","device_name","local_name","device_category","device_subcategory",
      "device_type","device_type_family","manufacturer","model","site_name",
      "network_scope_list","organization_zone_name","recommended_zone_name","edge_locations",
      "mac_list","ip_list","switch_name_list","switch_port_list","labels","purdue_level",
      "risk_score","os_name","combined_os","os_version","detector_name",
      "endpoint_security_names","edr_endpoint_status","edr_is_up_to_date_text",
      "infected","suspicious","first_seen_list","last_seen_list","last_seen_reported",
      "visibility_score","visibility_score_level","data_sources_seen_reported_from",
      "integration_types_reported_from","integrations_reported_from",
      "ot_criticality","criticality","equipment_class"
    ],
    "include_count": false,
    "tenant": "tenant-a",
    "total": 1000000,
    "delay_ms": 0
  }'
